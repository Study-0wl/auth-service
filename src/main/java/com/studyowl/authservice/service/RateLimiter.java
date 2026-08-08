package com.studyowl.authservice.service;

import com.studyowl.authservice.config.DynamoDbProperties;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

/**
 * Fixed-window rate limiter backed by DynamoDB (table: aws.dynamodb.rate-limits-table):
 * one item per (key, hour-bucket) pair, incremented via a conditional UpdateItem —
 * DynamoDB rejects the update (ConditionalCheckFailedException) once the count is
 * already at the limit, so the check-and-increment is race-free in a single call,
 * no read-then-write round trip, and works correctly across multiple instances.
 *
 * This is a fixed window, not the sliding window the in-memory version used to do —
 * slightly less precise (a request right at a window boundary could allow a small
 * burst) but that's an acceptable trade here: the goal is "roughly N per hour," not
 * exact enforcement, and DynamoDB doesn't offer an equivalent to a sliding deque
 * without a lot more complexity (a query across per-hit items instead of one counter).
 *
 * request-otp is unauthenticated and triggers a real SMS send, so it's the endpoint
 * an attacker would use to run up your SMS bill (toll fraud) or spam a stranger's
 * phone — this is what stands between "normal use" and that.
 */
@Component
public class RateLimiter {

    private final DynamoDbClient dynamoDbClient;
    private final DynamoDbProperties properties;

    public RateLimiter(DynamoDbClient dynamoDbClient, DynamoDbProperties properties) {
        this.dynamoDbClient = dynamoDbClient;
        this.properties = properties;
    }

    /**
     * @return true if the caller is under the limit (and the hit is recorded),
     *         false if this call should be rejected with 429.
     */
    public boolean tryConsume(String key, int maxPerHour) {
        Instant hourBucket = Instant.now().truncatedTo(ChronoUnit.HOURS);
        String itemKey = key + "#" + hourBucket.getEpochSecond();
        // A couple of hours past the window's end is plenty — TTL cleanup timing
        // doesn't need to be precise, just eventual.
        long expiresAt = hourBucket.plusSeconds(7200).getEpochSecond();

        Map<String, AttributeValue> itemKeyMap = Map.of("rateLimitKey", AttributeValue.builder().s(itemKey).build());
        Map<String, String> names = Map.of("#c", "count");
        Map<String, AttributeValue> values = new HashMap<>();
        values.put(":zero", AttributeValue.builder().n("0").build());
        values.put(":incr", AttributeValue.builder().n("1").build());
        values.put(":max", AttributeValue.builder().n(String.valueOf(maxPerHour)).build());
        values.put(":ttl", AttributeValue.builder().n(String.valueOf(expiresAt)).build());

        try {
            dynamoDbClient.updateItem(UpdateItemRequest.builder()
                    .tableName(properties.rateLimitsTable())
                    .key(itemKeyMap)
                    .updateExpression("SET #c = if_not_exists(#c, :zero) + :incr, expiresAt = if_not_exists(expiresAt, :ttl)")
                    .conditionExpression("attribute_not_exists(#c) OR #c < :max")
                    .expressionAttributeNames(names)
                    .expressionAttributeValues(values)
                    .build());
            return true;
        } catch (ConditionalCheckFailedException e) {
            return false;
        }
    }
}
