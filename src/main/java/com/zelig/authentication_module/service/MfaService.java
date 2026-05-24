package com.zelig.authentication_module.service;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.google.common.io.BaseEncoding;
import com.zelig.authentication_module.dto.LoginResponse;
import com.zelig.authentication_module.dto.MfaEnrollResponse;
import com.zelig.authentication_module.entity.MfaMethod;
import com.zelig.authentication_module.entity.User;
import com.zelig.authentication_module.repository.MfaMethodRepository;
import com.zelig.authentication_module.repository.UserRepository;
import com.zelig.authentication_module.service.otp.EmailOtpDeliveryService;
import com.zelig.authentication_module.service.otp.OtpChallengeService;
import com.zelig.authentication_module.service.otp.SmsSender;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class MfaService {

    private final UserRepository userRepository;
    private final MfaMethodRepository mfaMethodRepository;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;
    private final OtpChallengeService otpChallengeService;
    private final EmailOtpDeliveryService emailOtpDeliveryService;
    private final SmsSender smsSender;

    @Value("${app.name:Authentication Module}")
    private String appName;

    @Value("${mfa.otp.length:6}")
    private int otpLength;

    // --- TOTP ---

    public MfaEnrollResponse enrollTotp(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String secret = generateTotpSecret();
        MfaMethod method = getOrCreateMethod(user, MfaMethod.MfaType.TOTP);
        method.setTotpSecret(secret);
        method.setQrCodeUrl(buildOtpAuthUrl(user.getUsername(), secret));
        method.setVerified(false);
        mfaMethodRepository.save(method);

        return MfaEnrollResponse.builder()
                .secret(secret)
                .qrCodeUrl(method.getQrCodeUrl())
                .build();
    }

    public void confirmTotpEnrollment(Long userId, int code) {
        MfaMethod method = mfaMethodRepository.findByUserIdAndType(userId, MfaMethod.MfaType.TOTP)
                .orElseThrow(() -> new RuntimeException("TOTP not enrolled"));

        if (!verifyTotpCode(method.getTotpSecret(), code)) {
            throw new RuntimeException("Invalid verification code");
        }

        activateMfaMethod(method);
    }

    // --- Email OTP ---

    public void enrollEmailOtp(Long userId, String email) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String targetEmail = (email != null && !email.isBlank()) ? email : user.getEmail();
        if (targetEmail == null || targetEmail.isBlank()) {
            throw new RuntimeException("Email address is required for email OTP MFA");
        }

        MfaMethod method = getOrCreateMethod(user, MfaMethod.MfaType.EMAIL_OTP);
        method.setEmailAddress(targetEmail);
        method.setVerified(false);
        mfaMethodRepository.save(method);

        String code = otpChallengeService.generateAndStore(userId, MfaMethod.MfaType.EMAIL_OTP,
                OtpChallengeService.Purpose.ENROLLMENT);
        emailOtpDeliveryService.sendOtp(targetEmail, code, true);
        log.info("Email OTP enrollment started for user {}", user.getUsername());
    }

    public void confirmEmailOtpEnrollment(Long userId, int code) {
        verifyEnrollmentOtp(userId, MfaMethod.MfaType.EMAIL_OTP, code);
        MfaMethod method = mfaMethodRepository.findByUserIdAndType(userId, MfaMethod.MfaType.EMAIL_OTP)
                .orElseThrow(() -> new RuntimeException("Email OTP not enrolled"));
        activateMfaMethod(method);
    }

    // --- SMS OTP ---

    public void enrollSmsOtp(Long userId, String phoneNumber) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (phoneNumber == null || phoneNumber.isBlank()) {
            throw new RuntimeException("Phone number is required for SMS OTP MFA");
        }

        MfaMethod method = getOrCreateMethod(user, MfaMethod.MfaType.SMS_OTP);
        method.setPhoneNumber(normalizePhone(phoneNumber));
        method.setVerified(false);
        mfaMethodRepository.save(method);

        String code = otpChallengeService.generateAndStore(userId, MfaMethod.MfaType.SMS_OTP,
                OtpChallengeService.Purpose.ENROLLMENT);
        smsSender.sendOtp(method.getPhoneNumber(), code, true);
        log.info("SMS OTP enrollment started for user {}", user.getUsername());
    }

    public void confirmSmsOtpEnrollment(Long userId, int code) {
        verifyEnrollmentOtp(userId, MfaMethod.MfaType.SMS_OTP, code);
        MfaMethod method = mfaMethodRepository.findByUserIdAndType(userId, MfaMethod.MfaType.SMS_OTP)
                .orElseThrow(() -> new RuntimeException("SMS OTP not enrolled"));
        activateMfaMethod(method);
    }

    // --- Login challenge ---

    public void dispatchLoginOtp(User user) {
        findPrimaryMethod(user.getId()).ifPresent(method -> {
            switch (method.getType()) {
                case EMAIL_OTP -> sendLoginEmailOtp(user, method);
                case SMS_OTP -> sendLoginSmsOtp(user, method);
                case TOTP -> { /* client uses authenticator app */ }
                default -> log.debug("No OTP dispatch for MFA type {}", method.getType());
            }
        });
    }

    public void resendLoginOtp(String mfaToken) {
        Long userId = validateMfaToken(mfaToken);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        dispatchLoginOtp(user);
    }

    public String getPrimaryMethodType(Long userId) {
        return findPrimaryMethod(userId)
                .map(m -> m.getType().name())
                .orElse(null);
    }

    public LoginResponse verifyMfaAndLogin(String mfaToken, int code, String userAgent, String ipAddress) {
        Long userId = validateMfaToken(mfaToken);
        MfaMethod method = findPrimaryMethod(userId)
                .orElseThrow(() -> new RuntimeException("No primary MFA method configured"));

        boolean valid = switch (method.getType()) {
            case TOTP -> method.isVerified() && verifyTotpCode(method.getTotpSecret(), code);
            case EMAIL_OTP, SMS_OTP -> method.isVerified()
                    && otpChallengeService.verifyAndConsume(userId, method.getType(),
                    OtpChallengeService.Purpose.LOGIN, formatCode(code));
            default -> false;
        };

        if (!valid) {
            throw new RuntimeException("Invalid MFA code");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        return LoginResponse.builder()
                .accessToken(tokenService.generateAccessToken(user.getId(), user.getUsername()))
                .refreshToken(refreshTokenService.issue(user, userAgent, ipAddress))
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .mfaRequired(false)
                .build();
    }

    // --- Helpers ---

    private void sendLoginEmailOtp(User user, MfaMethod method) {
        String email = method.getEmailAddress();
        if (email == null || email.isBlank()) {
            throw new RuntimeException("Email OTP is not configured");
        }
        String code = otpChallengeService.generateAndStore(user.getId(), MfaMethod.MfaType.EMAIL_OTP,
                OtpChallengeService.Purpose.LOGIN);
        emailOtpDeliveryService.sendOtp(email, code, false);
    }

    private void sendLoginSmsOtp(User user, MfaMethod method) {
        String phone = method.getPhoneNumber();
        if (phone == null || phone.isBlank()) {
            throw new RuntimeException("SMS OTP is not configured");
        }
        String code = otpChallengeService.generateAndStore(user.getId(), MfaMethod.MfaType.SMS_OTP,
                OtpChallengeService.Purpose.LOGIN);
        smsSender.sendOtp(phone, code, false);
    }

    private void verifyEnrollmentOtp(Long userId, MfaMethod.MfaType type, int code) {
        if (!otpChallengeService.verifyAndConsume(userId, type, OtpChallengeService.Purpose.ENROLLMENT, formatCode(code))) {
            throw new RuntimeException("Invalid or expired verification code");
        }
    }

    private void activateMfaMethod(MfaMethod method) {
        method.setVerified(true);
        method.setVerifiedAt(LocalDateTime.now());
        setAsPrimary(method);
        mfaMethodRepository.save(method);

        User user = method.getUser();
        user.setMfaEnabled(true);
        userRepository.save(user);
        log.info("{} MFA enabled for user {}", method.getType(), user.getUsername());
    }

    private void setAsPrimary(MfaMethod method) {
        List<MfaMethod> all = mfaMethodRepository.findByUserId(method.getUser().getId());
        for (MfaMethod m : all) {
            m.setPrimary(m.getId().equals(method.getId()));
        }
        mfaMethodRepository.saveAll(all);
    }

    private MfaMethod getOrCreateMethod(User user, MfaMethod.MfaType type) {
        return mfaMethodRepository.findByUserIdAndType(user.getId(), type)
                .orElseGet(() -> MfaMethod.builder()
                        .user(user)
                        .type(type)
                        .isPrimary(false)
                        .isVerified(false)
                        .build());
    }

    private Optional<MfaMethod> findPrimaryMethod(Long userId) {
        return mfaMethodRepository.findByUserIdAndIsPrimaryTrue(userId).stream()
                .filter(MfaMethod::isVerified)
                .findFirst();
    }

    private Long validateMfaToken(String mfaToken) {
        if (!tokenService.isTokenValid(mfaToken) || tokenService.isTokenExpired(mfaToken)) {
            throw new RuntimeException("MFA session expired");
        }
        if (!tokenService.isTokenType(mfaToken, TokenService.TYPE_MFA)) {
            throw new RuntimeException("Invalid MFA token");
        }
        return tokenService.extractUserId(mfaToken);
    }

    private String formatCode(int code) {
        return String.format("%0" + otpLength + "d", code);
    }

    private static String normalizePhone(String phone) {
        return phone.replaceAll("[\\s()-]", "");
    }

    private boolean verifyTotpCode(String secret, int code) {
        try {
            TimeBasedOneTimePasswordGenerator generator = new TimeBasedOneTimePasswordGenerator();
            byte[] decoded = BaseEncoding.base32().decode(secret.toUpperCase());
            Key key = new javax.crypto.spec.SecretKeySpec(decoded, "HmacSHA1");
            int expected = generator.generateOneTimePassword(key, Instant.now());
            return expected == code;
        } catch (Exception e) {
            log.error("TOTP verification failed", e);
            return false;
        }
    }

    private String generateTotpSecret() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA1");
            keyGenerator.init(160);
            SecretKey key = keyGenerator.generateKey();
            return BaseEncoding.base32().omitPadding().encode(key.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate TOTP secret", e);
        }
    }

    private String buildOtpAuthUrl(String account, String secret) {
        String label = URLEncoder.encode(appName + ":" + account, StandardCharsets.UTF_8);
        String issuer = URLEncoder.encode(appName, StandardCharsets.UTF_8);
        return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + issuer;
    }
}
