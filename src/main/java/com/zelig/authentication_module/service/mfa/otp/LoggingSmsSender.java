package com.zelig.authentication_module.service.mfa.otp;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "mfa.sms.provider", havingValue = "log", matchIfMissing = false)
@Slf4j
public class LoggingSmsSender implements SmsSender {

    @Override
    public void sendOtp(String phoneNumber, String code, boolean enrollment) {
        log.warn("[DEV SMS OTP] to={} enrollment={} code={}", phoneNumber, enrollment, code);
    }
}
