package com.studyowl.authservice.service;

import com.studyowl.authservice.config.S3Properties;
import com.studyowl.authservice.dto.PhotoUploadUrlResponse;
import java.time.Duration;
import java.util.UUID;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;

/**
 * Issues a presigned S3 PUT URL so the client uploads the profile photo directly to
 * S3 — the file bytes never pass through this API server. See docs/openapi.yaml
 * for how this fits between confirm-otp and complete-profile.
 * <p>
 * No session/token validation here anymore — Kong's jwt plugin already rejected this
 * request before it arrived if the caller didn't hold a valid access token (see
 * kong/kong.yml). userId, from the X-User-Sub header AuthController reads, is just
 * used to namespace the S3 key.
 */
@Service
public class ProfilePhotoService {

    private static final Duration EXPIRY = Duration.ofMinutes(5);

    private final S3Presigner s3Presigner;
    private final S3Properties s3Properties;

    public ProfilePhotoService(S3Presigner s3Presigner, S3Properties s3Properties) {
        this.s3Presigner = s3Presigner;
        this.s3Properties = s3Properties;
    }

    public PhotoUploadUrlResponse createUploadUrl(String userId, String contentType) {
        String key = "profile-photos/" + userId + "/" + UUID.randomUUID() + "/" + sanitizeExtension(contentType);

        PutObjectRequest objectRequest = PutObjectRequest.builder()
                .bucket(s3Properties.profilePhotoBucket())
                .key(key)
                .contentType(contentType)
                .build();

        PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
                .signatureDuration(EXPIRY)
                .putObjectRequest(objectRequest)
                .build();

        PresignedPutObjectRequest presigned = s3Presigner.presignPutObject(presignRequest);

        String photoUrl = "https://%s.s3.amazonaws.com/%s".formatted(s3Properties.profilePhotoBucket(), key);

        return new PhotoUploadUrlResponse(presigned.url().toString(), photoUrl, (int) EXPIRY.toSeconds());
    }

    private String sanitizeExtension(String contentType) {
        String ext = switch (contentType) {
            case "image/png" -> "png";
            case "image/webp" -> "webp";
            default -> "jpg";
        };
        return "photo." + ext;
    }
}
