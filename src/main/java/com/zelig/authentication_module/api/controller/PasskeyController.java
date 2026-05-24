package com.zelig.authentication_module.api.controller;

import com.zelig.authentication_module.api.dto.*;
import com.zelig.authentication_module.api.util.RequestUtils;
import com.zelig.authentication_module.security.AuthenticatedUser;
import com.zelig.authentication_module.service.passkey.PasskeyService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

/**
 * WebAuthn / passkey registration and authentication (FIDO2).
 * <p>
 * Registration requires an access token. Authentication is public and follows the
 * two-step start/finish pattern required by the browser WebAuthn API.
 */
@RestController
@RequestMapping("/api/auth/passkey")
@RequiredArgsConstructor
public class PasskeyController {

    private final PasskeyService passkeyService;

    @PostMapping("/register/start")
    public ResponseEntity<RegistrationStartResponse> startRegistration(
            @AuthenticationPrincipal AuthenticatedUser user) throws IOException {
        return ResponseEntity.ok(passkeyService.startRegistration(user.getUserId()));
    }

    @PostMapping("/register/finish")
    public ResponseEntity<MessageResponse> finishRegistration(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestBody PasskeyRegistrationRequest request) {
        passkeyService.finishRegistration(user.getUserId(), request.getCredentialJson(), request.getDeviceName());
        return ResponseEntity.ok(new MessageResponse("Passkey registered successfully"));
    }

    @PostMapping("/authenticate/start")
    public ResponseEntity<PasskeyAuthenticationStartResponse> startAuthentication() throws IOException {
        return ResponseEntity.ok(passkeyService.startAuthentication());
    }

    @PostMapping("/authenticate/finish")
    public ResponseEntity<LoginResponse> finishAuthentication(
            @RequestBody PasskeyAuthenticationFinishRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(passkeyService.finishAuthentication(
                request.getSessionId(), request.getCredentialJson(),
                RequestUtils.userAgent(httpRequest), RequestUtils.clientIp(httpRequest)));
    }
}
