package com.studyowl.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "otp")
public record OtpProperties(
        int expirySeconds,
        RateLimit rateLimit
) {
    public record RateLimit(
            int maxRequestsPerPhonePerHour
    ) {
    }
}
