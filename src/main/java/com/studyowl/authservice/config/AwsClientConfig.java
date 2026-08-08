package com.studyowl.authservice.config;

import java.net.URI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClientBuilder;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;

/**
 * Cognito/S3 clients pick up AWS credentials via the SDK's default provider chain
 * (env vars, ~/.aws/credentials, or an EC2/ECS/Lambda instance role in production) —
 * there is deliberately no access key/secret in this codebase for those.
 *
 * DynamoDbClient is the one exception: when aws.dynamodb.endpoint-override is set
 * (local dev, pointing at the DynamoDB Local container in docker-compose.yml), it
 * uses dummy static credentials instead — DynamoDB Local doesn't validate them, and
 * the SDK still requires *some* credentials object to construct a client. In
 * production, endpoint-override is blank and this behaves exactly like the other
 * two clients: real region, real role-based credentials.
 */
@Configuration
public class AwsClientConfig {

    @Bean
    public CognitoIdentityProviderClient cognitoIdentityProviderClient(@Value("${aws.region}") String region) {
        return CognitoIdentityProviderClient.builder()
                .region(Region.of(region))
                .build();
    }

    @Bean
    public S3Presigner s3Presigner(@Value("${aws.region}") String region) {
        return S3Presigner.builder()
                .region(Region.of(region))
                .build();
    }

    @Bean
    public DynamoDbClient dynamoDbClient(@Value("${aws.region}") String region, DynamoDbProperties dynamoDbProperties) {
        DynamoDbClientBuilder builder = DynamoDbClient.builder().region(Region.of(region));

        if (dynamoDbProperties.isLocal()) {
            builder.endpointOverride(URI.create(dynamoDbProperties.endpointOverride()))
                    .credentialsProvider(StaticCredentialsProvider.create(
                            AwsBasicCredentials.create("local", "local")));
        }

        return builder.build();
    }
}
