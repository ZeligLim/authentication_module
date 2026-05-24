package com.zelig.authentication_module.service.passkey;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import com.zelig.authentication_module.api.dto.LoginResponse;
import com.zelig.authentication_module.api.dto.PasskeyAuthenticationStartResponse;
import com.zelig.authentication_module.api.dto.RegistrationStartResponse;
import com.zelig.authentication_module.domain.entity.PasskeyCredential;
import com.zelig.authentication_module.domain.entity.User;
import com.zelig.authentication_module.domain.repository.PasskeyCredentialRepository;
import com.zelig.authentication_module.domain.repository.UserRepository;
import com.zelig.authentication_module.service.auth.RefreshTokenService;
import com.zelig.authentication_module.service.auth.TokenService;
import com.zelig.authentication_module.service.mfa.MfaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * WebAuthn passkey registration and authentication using the Yubico java-webauthn-server library.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PasskeyService {

    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final UserRepository userRepository;
    private final RelyingParty relyingParty;
    private final ObjectMapper objectMapper;
    private final WebAuthnSessionStore sessionStore;
    private final TokenService tokenService;
    private final MfaService mfaService;
    private final RefreshTokenService refreshTokenService;

    public RegistrationStartResponse startRegistration(Long userId) throws IOException {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        UserIdentity userIdentity = UserIdentity.builder()
                .name(user.getUsername())
                .displayName(displayName(user))
                .id(new ByteArray(String.valueOf(user.getId()).getBytes(StandardCharsets.UTF_8)))
                .build();

        PublicKeyCredentialCreationOptions registrationOptions = relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(userIdentity)
                        .build()
        );

        sessionStore.storeRegistration(userId, registrationOptions);

        return RegistrationStartResponse.builder()
                .challenge(registrationOptions.getChallenge().getBase64Url())
                .options(objectMapper.writeValueAsString(registrationOptions))
                .build();
    }

    public void finishRegistration(Long userId, String credentialJson, String deviceName) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            PublicKeyCredentialCreationOptions request = sessionStore.consumeRegistration(userId);
            if (request == null) {
                throw new RuntimeException("Registration session expired or not found");
            }

            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential =
                    parseRegistrationCredential(credentialJson);

            RegistrationResult result = relyingParty.finishRegistration(
                    FinishRegistrationOptions.builder()
                            .request(request)
                            .response(credential)
                            .build()
            );

            PasskeyCredential passkeyCredential = PasskeyCredential.builder()
                    .user(user)
                    .credentialId(result.getKeyId().getId().getBase64Url())
                    .publicKey(result.getPublicKeyCose().getBytes())
                    .aaguid(result.getAaguid().getBytes())
                    .deviceName(deviceName != null ? deviceName : "Passkey")
                    .signatureCounter(result.getSignatureCount())
                    .userVerificationRequired(true)
                    .build();

            passkeyCredentialRepository.save(passkeyCredential);
            log.info("Passkey registered for user: {}", user.getUsername());

        } catch (RegistrationFailedException e) {
            log.error("Passkey registration failed: {}", e.getMessage());
            throw new RuntimeException("Passkey registration failed", e);
        } catch (IOException e) {
            log.error("Failed to parse credential: {}", e.getMessage());
            throw new RuntimeException("Failed to parse credential", e);
        }
    }

    public PasskeyAuthenticationStartResponse startAuthentication() throws IOException {
        AssertionRequest assertionRequest = relyingParty.startAssertion(
                StartAssertionOptions.builder().build()
        );

        String sessionId = sessionStore.storeAssertion(assertionRequest);

        return PasskeyAuthenticationStartResponse.builder()
                .sessionId(sessionId)
                .options(objectMapper.writeValueAsString(assertionRequest))
                .build();
    }

    public LoginResponse finishAuthentication(String sessionId, String credentialJson, String userAgent, String ipAddress) {
        try {
            AssertionRequest assertionRequest = sessionStore.consumeAssertion(sessionId);
            if (assertionRequest == null) {
                throw new RuntimeException("Authentication session expired or not found");
            }

            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential =
                    parseAssertionCredential(credentialJson);

            AssertionResult result = relyingParty.finishAssertion(
                    FinishAssertionOptions.builder()
                            .request(assertionRequest)
                            .response(credential)
                            .build()
            );

            if (!result.isSuccess()) {
                throw new RuntimeException("Passkey authentication failed");
            }

            String credentialId = credential.getId().getBase64Url();
            PasskeyCredential stored = passkeyCredentialRepository.findByCredentialId(credentialId)
                    .orElseThrow(() -> new RuntimeException("Passkey credential not found"));

            User user = stored.getUser();
            user.setLastLoginAt(LocalDateTime.now());
            userRepository.save(user);

            stored.setSignatureCounter(result.getSignatureCount());
            stored.setLastUsedAt(LocalDateTime.now());
            passkeyCredentialRepository.save(stored);

            log.info("User {} authenticated via passkey", user.getUsername());

            if (user.isMfaEnabled()) {
                String mfaToken = tokenService.generateMfaToken(user.getId());
                mfaService.dispatchLoginOtp(user);
                return LoginResponse.builder()
                        .mfaRequired(true)
                        .mfaToken(mfaToken)
                        .mfaMethod(mfaService.getPrimaryMethodType(user.getId()))
                        .userId(user.getId())
                        .username(user.getUsername())
                        .email(user.getEmail())
                        .build();
            }

            return buildLoginResponse(user, userAgent, ipAddress);

        } catch (AssertionFailedException e) {
            log.error("Passkey authentication failed: {}", e.getMessage());
            throw new RuntimeException("Passkey authentication failed", e);
        } catch (IOException e) {
            log.error("Failed to parse assertion response: {}", e.getMessage());
            throw new RuntimeException("Failed to parse assertion response", e);
        }
    }

    private LoginResponse buildLoginResponse(User user, String userAgent, String ipAddress) {
        return LoginResponse.builder()
                .accessToken(tokenService.generateAccessToken(user.getId(), user.getUsername()))
                .refreshToken(refreshTokenService.issue(user, userAgent, ipAddress))
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .mfaRequired(false)
                .build();
    }

    private String displayName(User user) {
        if (user.getFirstName() != null && user.getLastName() != null) {
            return user.getFirstName() + " " + user.getLastName();
        }
        return user.getUsername();
    }

    private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> parseRegistrationCredential(
            String credentialJson) throws IOException {
        if (credentialJson == null || credentialJson.isBlank()) {
            throw new IllegalArgumentException("credentialJson is required");
        }
        return objectMapper.readValue(credentialJson,
                new TypeReference<PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>>() {});
    }

    private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> parseAssertionCredential(
            String credentialJson) throws IOException {
        if (credentialJson == null || credentialJson.isBlank()) {
            throw new IllegalArgumentException("credentialJson is required");
        }
        return objectMapper.readValue(credentialJson,
                new TypeReference<PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>>() {});
    }
}
