package com.studyowl.authservice.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ResourceInUseException;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import software.amazon.awssdk.services.dynamodb.model.TimeToLiveSpecification;
import software.amazon.awssdk.services.dynamodb.model.UpdateTimeToLiveRequest;
import software.amazon.awssdk.services.dynamodb.waiters.DynamoDbWaiter;

/**
 * Local dev only: creates the rate-limits DynamoDB table (with TTL enabled on
 * `expiresAt`) on startup if it doesn't already exist, so `docker compose up` +
 * `mvn spring-boot:run` just works with no manual setup step. Never runs against
 * real AWS — production
 * tables are provisioned separately (console/IaC), matching how the S3 bucket and
 * Cognito pool were set up; the app should never hold CreateTable permission in
 * production (see the least-privilege IAM policy in README.md).
 */
@Component
public class DynamoDbTableInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DynamoDbTableInitializer.class);

    private final DynamoDbClient dynamoDbClient;
    private final DynamoDbProperties properties;

    public DynamoDbTableInitializer(DynamoDbClient dynamoDbClient, DynamoDbProperties properties) {
        this.dynamoDbClient = dynamoDbClient;
        this.properties = properties;
    }

    @Override
    public void run(String... args) {
        if (!properties.isLocal()) {
            return;
        }
        createTableIfMissing(properties.rateLimitsTable(), "rateLimitKey");
    }

    private void createTableIfMissing(String tableName, String partitionKeyName) {
        try {
            dynamoDbClient.createTable(CreateTableRequest.builder()
                    .tableName(tableName)
                    .billingMode(BillingMode.PAY_PER_REQUEST)
                    .attributeDefinitions(AttributeDefinition.builder()
                            .attributeName(partitionKeyName)
                            .attributeType(ScalarAttributeType.S)
                            .build())
                    .keySchema(KeySchemaElement.builder()
                            .attributeName(partitionKeyName)
                            .keyType(KeyType.HASH)
                            .build())
                    .build());

            try (DynamoDbWaiter waiter = DynamoDbWaiter.builder().client(dynamoDbClient).build()) {
                waiter.waitUntilTableExists(b -> b.tableName(tableName));
            }

            dynamoDbClient.updateTimeToLive(UpdateTimeToLiveRequest.builder()
                    .tableName(tableName)
                    .timeToLiveSpecification(TimeToLiveSpecification.builder()
                            .attributeName("expiresAt")
                            .enabled(true)
                            .build())
                    .build());

            log.info("Created local DynamoDB table '{}' with TTL on expiresAt", tableName);
        } catch (ResourceInUseException e) {
            // Table already exists (e.g. container restarted with a persisted volume) — fine.
            log.debug("DynamoDB table '{}' already exists", tableName);
        }
    }
}
