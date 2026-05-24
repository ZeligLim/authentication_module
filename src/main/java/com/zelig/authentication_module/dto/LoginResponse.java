package com.zelig.authentication_module.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class LoginResponse {
    private String accessToken;
    private String refreshToken;
    private String mfaToken;
    private Long userId;
    private String username;
    private String email;
    private boolean mfaRequired;
    /** Primary MFA method when mfaRequired is true: TOTP, EMAIL_OTP, SMS_OTP */
    private String mfaMethod;
}