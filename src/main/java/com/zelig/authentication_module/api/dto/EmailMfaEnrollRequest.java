package com.zelig.authentication_module.api.dto;

import jakarta.validation.constraints.Email;
import lombok.Data;

@Data
public class EmailMfaEnrollRequest {
    /** Optional; defaults to the authenticated user's email. */
    @Email
    private String email;
}
