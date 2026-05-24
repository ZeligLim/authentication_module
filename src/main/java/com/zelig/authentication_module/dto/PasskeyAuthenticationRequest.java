package com.zelig.authentication_module.dto;

import lombok.Data;

@Data
public class PasskeyAuthenticationRequest {
    private String username;
    private String clientDataJSON;
    private String authenticatorData;
    private String signature;
}