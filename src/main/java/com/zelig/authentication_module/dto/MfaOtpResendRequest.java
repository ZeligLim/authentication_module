package com.zelig.authentication_module.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class MfaOtpResendRequest {
    @NotBlank
    private String mfaToken;
}
