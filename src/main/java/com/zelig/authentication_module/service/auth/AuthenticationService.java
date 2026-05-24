package com.zelig.authentication_module.service.auth;

import com.zelig.authentication_module.api.dto.LoginResponse;
import com.zelig.authentication_module.api.dto.RegisterRequest;
import com.zelig.authentication_module.domain.entity.User;
import com.zelig.authentication_module.domain.repository.UserRepository;
import com.zelig.authentication_module.service.mfa.MfaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Orchestrates sign-in flows (password, magic link) and issues JWT access/refresh token pairs.
 * Delegates MFA challenges to {@link MfaService} and refresh rotation to {@link RefreshTokenService}.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final MfaService mfaService;

    public LoginResponse validateMagicLink(String token, String userAgent, String ipAddress) {
        if (!tokenService.isTokenValid(token) || tokenService.isTokenExpired(token)) {
            throw new RuntimeException("Magic link expired or invalid");
        }
        if (!tokenService.isTokenType(token, TokenService.TYPE_MAGIC_LINK)) {
            throw new RuntimeException("Invalid magic link token");
        }

        Long userId = tokenService.extractUserId(token);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setLastLoginAt(LocalDateTime.now());
        user.setEmailVerified(true);
        userRepository.save(user);

        log.info("User {} logged in via magic link", user.getUsername());
        return completeLogin(user, userAgent, ipAddress);
    }

    public LoginResponse loginWithPassword(String username, String password, String userAgent, String ipAddress) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (user.getPasswordHash() == null || user.getPasswordHash().isBlank()) {
            throw new RuntimeException("Password login not available for this account");
        }

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new RuntimeException("Invalid credentials");
        }

        if (!user.isActive()) {
            throw new RuntimeException("User account is disabled");
        }

        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        log.info("User {} logged in with password", user.getUsername());
        return completeLogin(user, userAgent, ipAddress);
    }

    public LoginResponse refreshAccessToken(String refreshToken, String userAgent, String ipAddress) {
        return refreshTokenService.rotate(refreshToken, userAgent, ipAddress);
    }

    public void logout(String refreshToken) {
        refreshTokenService.revoke(refreshToken);
    }

    public void logoutAll(Long userId) {
        refreshTokenService.revokeAllForUser(userId);
    }

    public LoginResponse register(RegisterRequest request, String userAgent, String ipAddress) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already taken");
        }
        if (request.getEmail() != null && userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .mfaEnabled(false)
                .emailVerified(request.getEmail() == null)
                .active(true)
                .build();

        user = userRepository.save(user);
        log.info("Registered user {}", user.getUsername());
        return completeLogin(user, userAgent, ipAddress);
    }

    public LoginResponse completeLogin(User user) {
        return completeLogin(user, null, null);
    }

    public LoginResponse completeLogin(User user, String userAgent, String ipAddress) {
        if (user.isMfaEnabled()) {
            String mfaToken = tokenService.generateMfaToken(user.getId());
            mfaService.dispatchLoginOtp(user);
            return LoginResponse.builder()
                    .mfaRequired(true)
                    .mfaToken(mfaToken)
                    .mfaMethod(mfaService.getPrimaryMethodType(user.getId()))
                    .userId(user.getId())
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .build();
        }

        return issueTokens(user, userAgent, ipAddress);
    }

    public LoginResponse issueTokens(User user, String userAgent, String ipAddress) {
        return LoginResponse.builder()
                .accessToken(tokenService.generateAccessToken(user.getId(), user.getUsername()))
                .refreshToken(refreshTokenService.issue(user, userAgent, ipAddress))
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .mfaRequired(false)
                .build();
    }
}
