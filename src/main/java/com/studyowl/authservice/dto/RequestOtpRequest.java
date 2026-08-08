package com.studyowl.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RequestOtpRequest(
        @NotBlank
        @Pattern(
                regexp = "^\\+[1-9]\\d{1,14}$|^[^\\s@]+@[^\\s@]+$",
                message = "identifier must be an E.164 phone number (e.g. +919876543210) or a valid email address"
        )
        String identifier
) {
}
