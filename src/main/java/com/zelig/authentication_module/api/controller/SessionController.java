package com.zelig.authentication_module.api.controller;

import com.zelig.authentication_module.api.dto.*;
import com.zelig.authentication_module.api.util.RequestUtils;
import com.zelig.authentication_module.security.AuthenticatedUser;
import com.zelig.authentication_module.service.auth.AuthenticationService;
import com.zelig.authentication_module.service.auth.EmailSignInService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * Core session lifecycle: register, login, token refresh, logout, and magic-link email sign-in.
 * <p>
 * All successful logins return {@link LoginResponse}. When MFA is enabled, {@code mfaRequired=true}
 * and the client must call {@link MfaController} before using access tokens.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class SessionController {

    private final AuthenticationService authenticationService;
    private final EmailSignInService emailSignInService;

    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authenticationService.register(
                request, RequestUtils.userAgent(httpRequest), RequestUtils.clientIp(httpRequest)));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authenticationService.loginWithPassword(
                request.getUsername(), request.getPassword(),
                RequestUtils.userAgent(httpRequest), RequestUtils.clientIp(httpRequest)));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authenticationService.refreshAccessToken(
                request.getRefreshToken(),
                RequestUtils.userAgent(httpRequest), RequestUtils.clientIp(httpRequest)));
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
                token, RequestUtils.userAgent(httpRequest), RequestUtils.clientIp(httpRequest)));
    }
}
