package com.zelig.authentication_module.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class MfaEnrollResponse {
    private String secret;
    private String qrCodeUrl;
}
