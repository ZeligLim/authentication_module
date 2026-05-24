package com.zelig.authentication_module.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SmsMfaEnrollRequest {
    @NotBlank
    private String phoneNumber;
}
