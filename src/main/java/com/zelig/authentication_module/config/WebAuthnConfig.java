package com.zelig.authentication_module.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.zelig.authentication_module.domain.repository.PasskeyCredentialRepository;
import com.zelig.authentication_module.service.passkey.JpaCredentialRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;

/**
 * WebAuthn configuration: creates RelyingParty and ObjectMapper beans.
 */
@Configuration
public class WebAuthnConfig {

    @Value("${webauthn.rp.name:Authentication Module}")
    private String rpName;

    @Value("${webauthn.rp.id:localhost}")
    private String rpId;

    @Value("${webauthn.origin:http://localhost:8080}")
    private String origin;

    @Bean
    public RelyingParty relyingParty(PasskeyCredentialRepository passkeyCredentialRepository) {
        // Provide a CredentialRepository implementation before build()
        JpaCredentialRepository credentialRepo = new JpaCredentialRepository(passkeyCredentialRepository);

        return RelyingParty.builder()
                .identity(RelyingPartyIdentity.builder()
                        .id(rpId)
                        .name(rpName)
                        .build())
                .credentialRepository(credentialRepo)
                .origins(Collections.singleton(origin))
                .build();
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
}