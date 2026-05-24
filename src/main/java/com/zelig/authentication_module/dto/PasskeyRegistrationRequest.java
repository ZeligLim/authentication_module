package com.zelig.authentication_module.dto;

import lombok.Data;

@Data
public class PasskeyRegistrationRequest {
    /** Full PublicKeyCredential JSON from the browser WebAuthn API. */
    private String credentialJson;
    private String deviceName;
}