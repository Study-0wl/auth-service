package com.studyowl.authservice.dto;

public record Tokens(
        String idToken,
        String accessToken,
        String refreshToken,
        int expiresIn
) {
}
