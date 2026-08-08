package com.studyowl.authservice.dto;

import jakarta.validation.constraints.NotBlank;

// No profileToken - see CompleteProfileRequest's comment; same X-User-Sub mechanism.
public record PhotoUploadUrlRequest(
        @NotBlank
        String contentType
) {
}
