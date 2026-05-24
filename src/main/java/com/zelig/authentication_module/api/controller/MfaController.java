package com.zelig.authentication_module.api.controller;

import com.zelig.authentication_module.api.dto.*;
import com.zelig.authentication_module.api.util.RequestUtils;
import com.zelig.authentication_module.security.AuthenticatedUser;
import com.zelig.authentication_module.service.mfa.MfaService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * Multi-factor authentication: TOTP (authenticator app), email OTP, and SMS OTP.
 * <p>
 * Enrollment endpoints require a valid access token. Login verification endpoints
 * ({@code /mfa/verify}, {@code /mfa/otp/resend}) use the short-lived {@code mfaToken}
 * returned when {@code mfaRequired=true}.
 */
@RestController
@RequestMapping("/api/auth/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final MfaService mfaService;

    // --- TOTP (Google Authenticator, etc.) ---

    @PostMapping("/totp/enroll")
    public ResponseEntity<MfaEnrollResponse> enrollTotp(@AuthenticationPrincipal AuthenticatedUser user) {
        return ResponseEntity.ok(mfaService.enrollTotp(user.getUserId()));
    }

    @PostMapping("/totp/confirm")
    public ResponseEntity<MessageResponse> confirmTotp(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestParam int code) {
        mfaService.confirmTotpEnrollment(user.getUserId(), code);
        return ResponseEntity.ok(new MessageResponse("MFA enabled successfully"));
    }

    // --- Email OTP ---

    @PostMapping("/email/enroll")
    public ResponseEntity<MessageResponse> enrollEmailOtp(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestBody(required = false) EmailMfaEnrollRequest request) {
        String email = request != null ? request.getEmail() : null;
        mfaService.enrollEmailOtp(user.getUserId(), email);
        return ResponseEntity.ok(new MessageResponse("Verification code sent to your email"));
    }

    @PostMapping("/email/confirm")
    public ResponseEntity<MessageResponse> confirmEmailOtp(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestParam int code) {
        mfaService.confirmEmailOtpEnrollment(user.getUserId(), code);
        return ResponseEntity.ok(new MessageResponse("Email MFA enabled successfully"));
    }

    // --- SMS OTP ---

    @PostMapping("/sms/enroll")
    public ResponseEntity<MessageResponse> enrollSmsOtp(
            @AuthenticationPrincipal AuthenticatedUser user,
            @Valid @RequestBody SmsMfaEnrollRequest request) {
        mfaService.enrollSmsOtp(user.getUserId(), request.getPhoneNumber());
        return ResponseEntity.ok(new MessageResponse("Verification code sent via SMS"));
    }

    @PostMapping("/sms/confirm")
    public ResponseEntity<MessageResponse> confirmSmsOtp(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestParam int code) {
        mfaService.confirmSmsOtpEnrollment(user.getUserId(), code);
        return ResponseEntity.ok(new MessageResponse("SMS MFA enabled successfully"));
    }

    // --- Login step (after primary auth returned mfaToken) ---

    @PostMapping("/otp/resend")
    public ResponseEntity<MessageResponse> resendLoginOtp(@Valid @RequestBody MfaOtpResendRequest request) {
        mfaService.resendLoginOtp(request.getMfaToken());
        return ResponseEntity.ok(new MessageResponse("Verification code resent"));
    }

    @PostMapping("/verify")
    public ResponseEntity<LoginResponse> verifyMfa(
            @Valid @RequestBody MfaVerifyRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(mfaService.verifyMfaAndLogin(
                request.getMfaToken(), request.getCode(),
                RequestUtils.userAgent(httpRequest), RequestUtils.clientIp(httpRequest)));
    }
}
