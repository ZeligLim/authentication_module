package com.zelig.authentication_module.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class RegistrationStartResponse {
    private String options;
    private String challenge;
}