package com.studyowl.authservice.dto;

public record ErrorResponse(
        String code,
        String message,
        // Only populated on 429 responses.
        Integer retryAfterSeconds
) {
    public ErrorResponse(String code, String message) {
        this(code, message, null);
    }
}
