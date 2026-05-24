package com.zelig.authentication_module.controller;

import com.zelig.authentication_module.dto.*;
import com.zelig.authentication_module.security.AuthenticatedUser;
import com.zelig.authentication_module.service.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;
    private final EmailSignInService emailSignInService;
    private final PasskeyService passkeyService;
    private final MfaService mfaService;

    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authenticationService.register(
                request, httpRequest.getHeader("User-Agent"), clientIp(httpRequest)));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authenticationService.loginWithPassword(
                request.getUsername(), request.getPassword(),
                httpRequest.getHeader("User-Agent"), clientIp(httpRequest)));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authenticationService.refreshAccessToken(
                request.getRefreshToken(),
                httpRequest.getHeader("User-Agent"),
                clientIp(httpRequest)));
    }

    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(@Valid @RequestBody LogoutRequest request) {
        authenticationService.logout(request.getRefreshToken());
        return ResponseEntity.ok(new MessageResponse("Logged out"));
    }

    @PostMapping("/logout/all")
    public ResponseEntity<MessageResponse> logoutAll(@AuthenticationPrincipal AuthenticatedUser user) {
        authenticationService.logoutAll(user.getUserId());
        return ResponseEntity.ok(new MessageResponse("All sessions revoked"));
    }

    @PostMapping("/login/email")
    public ResponseEntity<MessageResponse> requestEmailSignIn(@Valid @RequestBody EmailSignInRequest request) {
        emailSignInService.sendSignInLink(request.getEmail());
        return ResponseEntity.ok(new MessageResponse("Sign-in link sent to your email"));
    }

    @GetMapping("/magic-link")
    public ResponseEntity<LoginResponse> validateMagicLink(
            @RequestParam String token,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authenticationService.validateMagicLink(
                token, httpRequest.getHeader("User-Agent"), clientIp(httpRequest)));
    }

    @PostMapping("/passkey/register/start")
    public ResponseEntity<RegistrationStartResponse> startPasskeyRegistration(
            @AuthenticationPrincipal AuthenticatedUser user) throws IOException {
        return ResponseEntity.ok(passkeyService.startRegistration(user.getUserId()));
    }

    @PostMapping("/passkey/register/finish")
    public ResponseEntity<MessageResponse> finishPasskeyRegistration(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestBody PasskeyRegistrationRequest request) {
        passkeyService.finishRegistration(user.getUserId(), request.getCredentialJson(), request.getDeviceName());
        return ResponseEntity.ok(new MessageResponse("Passkey registered successfully"));
    }

    @PostMapping("/passkey/authenticate/start")
    public ResponseEntity<PasskeyAuthenticationStartResponse> startPasskeyAuthentication() throws IOException {
        return ResponseEntity.ok(passkeyService.startAuthentication());
    }

    @PostMapping("/passkey/authenticate/finish")
    public ResponseEntity<LoginResponse> finishPasskeyAuthentication(
            @RequestBody PasskeyAuthenticationFinishRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(passkeyService.finishAuthentication(
                request.getSessionId(), request.getCredentialJson(),
                httpRequest.getHeader("User-Agent"), clientIp(httpRequest)));
    }

    @PostMapping("/mfa/totp/enroll")
    public ResponseEntity<MfaEnrollResponse> enrollTotp(@AuthenticationPrincipal AuthenticatedUser user) {
        return ResponseEntity.ok(mfaService.enrollTotp(user.getUserId()));
    }

    @PostMapping("/mfa/totp/confirm")
    public ResponseEntity<MessageResponse> confirmTotp(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestParam int code) {
        mfaService.confirmTotpEnrollment(user.getUserId(), code);
        return ResponseEntity.ok(new MessageResponse("MFA enabled successfully"));
    }

    @PostMapping("/mfa/email/enroll")
    public ResponseEntity<MessageResponse> enrollEmailOtp(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestBody(required = false) EmailMfaEnrollRequest request) {
        String email = request != null ? request.getEmail() : null;
        mfaService.enrollEmailOtp(user.getUserId(), email);
        return ResponseEntity.ok(new MessageResponse("Verification code sent to your email"));
    }

    @PostMapping("/mfa/email/confirm")
    public ResponseEntity<MessageResponse> confirmEmailOtp(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestParam int code) {
        mfaService.confirmEmailOtpEnrollment(user.getUserId(), code);
        return ResponseEntity.ok(new MessageResponse("Email MFA enabled successfully"));
    }

    @PostMapping("/mfa/sms/enroll")
    public ResponseEntity<MessageResponse> enrollSmsOtp(
            @AuthenticationPrincipal AuthenticatedUser user,
            @Valid @RequestBody SmsMfaEnrollRequest request) {
        mfaService.enrollSmsOtp(user.getUserId(), request.getPhoneNumber());
        return ResponseEntity.ok(new MessageResponse("Verification code sent via SMS"));
    }

    @PostMapping("/mfa/sms/confirm")
    public ResponseEntity<MessageResponse> confirmSmsOtp(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestParam int code) {
        mfaService.confirmSmsOtpEnrollment(user.getUserId(), code);
        return ResponseEntity.ok(new MessageResponse("SMS MFA enabled successfully"));
    }

    @PostMapping("/mfa/otp/resend")
    public ResponseEntity<MessageResponse> resendLoginOtp(@Valid @RequestBody MfaOtpResendRequest request) {
        mfaService.resendLoginOtp(request.getMfaToken());
        return ResponseEntity.ok(new MessageResponse("Verification code resent"));
    }

    @PostMapping("/mfa/verify")
    public ResponseEntity<LoginResponse> verifyMfa(
            @Valid @RequestBody MfaVerifyRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(mfaService.verifyMfaAndLogin(
                request.getMfaToken(), request.getCode(),
                httpRequest.getHeader("User-Agent"), clientIp(httpRequest)));
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
