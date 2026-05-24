package com.zelig.authentication_module.service;

import com.zelig.authentication_module.entity.User;
import com.zelig.authentication_module.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class EmailSignInService {

    private final UserRepository userRepository;
    private final JavaMailSender mailSender;
    private final TokenService tokenService;

    @Value("${app.base-url:http://localhost:8080}")
    private String appBaseUrl;

    public void sendSignInLink(String email) {
        Optional<User> user = userRepository.findByEmail(email);

        if (user.isEmpty()) {
            User newUser = User.builder()
                    .username(UUID.randomUUID().toString())
                    .email(email)
                    .passwordHash("")
                    .mfaEnabled(false)
                    .emailVerified(false)
                    .active(true)
                    .build();
            user = Optional.of(userRepository.save(newUser));
        }

        String token = tokenService.generateMagicLinkToken(user.get().getId());
        String magicLink = appBaseUrl + "/api/auth/magic-link?token=" + token;
        sendMagicLinkEmail(email, magicLink);

        log.info("Sign-in link sent to: {}", email);
    }

    private void sendMagicLinkEmail(String email, String magicLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Your Sign-In Link");
        message.setText("Click to sign in: " + magicLink + "\n\nThis link expires in 15 minutes.");

        try {
            mailSender.send(message);
        } catch (Exception e) {
            log.error("Failed to send email to: {}", email, e);
            throw new RuntimeException("Failed to send email", e);
        }
    }
}
