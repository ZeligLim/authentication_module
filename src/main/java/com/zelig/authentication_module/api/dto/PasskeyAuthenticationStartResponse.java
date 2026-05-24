package com.zelig.authentication_module.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class PasskeyAuthenticationStartResponse {
    private String sessionId;
    private String options;
}
