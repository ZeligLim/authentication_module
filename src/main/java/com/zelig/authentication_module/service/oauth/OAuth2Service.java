package com.zelig.authentication_module.service.oauth;

import com.zelig.authentication_module.domain.entity.OAuth2Account;
import com.zelig.authentication_module.domain.entity.User;
import com.zelig.authentication_module.domain.repository.OAuth2AccountRepository;
import com.zelig.authentication_module.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
public class OAuth2Service {

    private final UserRepository userRepository;
    private final OAuth2AccountRepository oauth2AccountRepository;

    public User findOrCreateUser(String provider, OAuth2User oauth2User) {
        String providerUserId = oauth2User.getName();

        // Check if OAuth2 account exists
        Optional<OAuth2Account> existingAccount = oauth2AccountRepository
            .findByProviderAndProviderUserId(provider, providerUserId);

        if (existingAccount.isPresent()) {
            User user = existingAccount.get().getUser();
            user.setLastLoginAt(java.time.LocalDateTime.now());
            return userRepository.save(user);
        }

        // Create new user from OAuth2 details
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");

        User user = User.builder()
            .username(email != null ? email : provider + "_" + providerUserId)
            .email(email)
            .firstName(name != null ? name.split(" ")[0] : "")
            .passwordHash("") // OAuth2 users don't need password initially
            .mfaEnabled(false)
            .emailVerified(email != null)
            .active(true)
            .build();

        user = userRepository.save(user);

        // Create OAuth2Account
        OAuth2Account oauth2Account = OAuth2Account.builder()
            .user(user)
            .provider(provider)
            .providerUserId(providerUserId)
            .displayName(name)
            .profilePictureUrl(oauth2User.getAttribute("picture"))
            .email(email)
            .build();

        oauth2AccountRepository.save(oauth2Account);
        user.setLastLoginAt(java.time.LocalDateTime.now());
        return userRepository.save(user);
    }

    public void linkOAuth2Account(User user, String provider, OAuth2User oauth2User) {
        String providerUserId = oauth2User.getName();

        OAuth2Account oauth2Account = OAuth2Account.builder()
            .user(user)
            .provider(provider)
            .providerUserId(providerUserId)
            .displayName(oauth2User.getAttribute("name"))
            .profilePictureUrl(oauth2User.getAttribute("picture"))
            .email(oauth2User.getAttribute("email"))
            .build();

        oauth2AccountRepository.save(oauth2Account);
    }
}