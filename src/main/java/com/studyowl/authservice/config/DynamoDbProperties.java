package com.studyowl.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * endpointOverride is blank in production (the SDK talks to real regional DynamoDB
 * using the same IAM role as Cognito/S3). Set it to point at DynamoDB Local
 * (see docker-compose.yml) for local dev — see AwsClientConfig for how that switches
 * the client to dummy credentials and triggers table auto-creation on startup.
 */
@ConfigurationProperties(prefix = "aws.dynamodb")
public record DynamoDbProperties(
        String endpointOverride,
        String rateLimitsTable
) {
    public boolean isLocal() {
        return endpointOverride != null && !endpointOverride.isBlank();
    }
}
