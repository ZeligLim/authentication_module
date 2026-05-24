package com.zelig.authentication_module.dto;

import lombok.Data;

@Data
public class PasskeyAuthenticationFinishRequest {
    private String sessionId;
    private String credentialJson;
}
