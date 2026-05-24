package com.zelig.authentication_module.service.mfa.otp;

import com.zelig.authentication_module.domain.entity.MfaMethod;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class OtpChallengeService {

    public enum Purpose {
        ENROLLMENT,
        LOGIN
    }

    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    private final Map<String, StoredChallenge> challenges = new ConcurrentHashMap<>();

    @Value("${mfa.otp.length:6}")
    private int otpLength;

    @Value("${mfa.otp.expiry-minutes:10}")
    private int expiryMinutes;

    @Value("${mfa.otp.max-attempts:5}")
    private int maxAttempts;

    public String generateAndStore(Long userId, MfaMethod.MfaType type, Purpose purpose) {
        String code = generateCode();
        String key = challengeKey(userId, type, purpose);
        challenges.put(key, new StoredChallenge(
                passwordEncoder.encode(code),
                Instant.now().plusSeconds(expiryMinutes * 60L),
                0
        ));
        return code;
    }

    public boolean verifyAndConsume(Long userId, MfaMethod.MfaType type, Purpose purpose, String code) {
        String key = challengeKey(userId, type, purpose);
        StoredChallenge challenge = challenges.get(key);
        if (challenge == null) {
            return false;
        }
        if (challenge.isExpired()) {
            challenges.remove(key);
            return false;
        }
        if (challenge.attempts() >= maxAttempts) {
            challenges.remove(key);
            throw new RuntimeException("Too many invalid OTP attempts");
        }

        if (!passwordEncoder.matches(code, challenge.codeHash())) {
            challenges.put(key, challenge.withAttempts(challenge.attempts() + 1));
            return false;
        }

        challenges.remove(key);
        return true;
    }

    public void invalidate(Long userId, MfaMethod.MfaType type, Purpose purpose) {
        challenges.remove(challengeKey(userId, type, purpose));
    }

    private String generateCode() {
        int bound = (int) Math.pow(10, otpLength);
        int code = secureRandom.nextInt(bound);
        return String.format("%0" + otpLength + "d", code);
    }

    private static String challengeKey(Long userId, MfaMethod.MfaType type, Purpose purpose) {
        return purpose.name().toLowerCase() + ":" + userId + ":" + type.name();
    }

    private record StoredChallenge(String codeHash, Instant expiresAt, int attempts) {
        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }

        StoredChallenge withAttempts(int newAttempts) {
            return new StoredChallenge(codeHash, expiresAt, newAttempts);
        }
    }
}
