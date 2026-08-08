package com.studyowl.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "aws.cognito")
public record CognitoProperties(
        String userPoolId,
        String clientId,
        String clientSecret
) {
    public boolean hasClientSecret() {
        return clientSecret != null && !clientSecret.isBlank();
    }
}
