package com.studyowl.authservice.dto;

public record PhotoUploadUrlResponse(
        String uploadUrl,
        String photoUrl,
        int expiresInSeconds
) {
}
