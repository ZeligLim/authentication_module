package com.zelig.authentication_module.service.mfa.otp;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailOtpDeliveryService {

    private final JavaMailSender mailSender;

    @Value("${app.name:Authentication Module}")
    private String appName;

    @Value("${mfa.otp.expiry-minutes:10}")
    private int expiryMinutes;

    public void sendOtp(String email, String code, boolean enrollment) {
        String subject = enrollment
                ? appName + " — verify your email for MFA"
                : appName + " — your sign-in code";

        String body = enrollment
                ? "Your verification code is: " + code + "\n\nEnter this code to enable email MFA. It expires in "
                + expiryMinutes + " minutes."
                : "Your sign-in code is: " + code + "\n\nIt expires in " + expiryMinutes + " minutes.";

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject(subject);
        message.setText(body);

        try {
            mailSender.send(message);
            log.info("Email OTP sent to {}", maskEmail(email));
        } catch (Exception e) {
            log.error("Failed to send email OTP to {}", maskEmail(email), e);
            throw new RuntimeException("Failed to send email OTP", e);
        }
    }

    private static String maskEmail(String email) {
        int at = email.indexOf('@');
        if (at <= 1) {
            return "***";
        }
        return email.charAt(0) + "***" + email.substring(at);
    }
}
