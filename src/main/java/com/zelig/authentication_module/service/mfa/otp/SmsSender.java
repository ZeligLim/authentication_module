package com.zelig.authentication_module.service.mfa.otp;

public interface SmsSender {
    void sendOtp(String phoneNumber, String code, boolean enrollment);
}
