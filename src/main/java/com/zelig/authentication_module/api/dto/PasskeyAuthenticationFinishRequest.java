package com.zelig.authentication_module.api.dto;

import lombok.Data;

@Data
public class PasskeyAuthenticationFinishRequest {
    private String sessionId;
    private String credentialJson;
}
