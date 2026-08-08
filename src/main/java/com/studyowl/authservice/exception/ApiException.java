package com.studyowl.authservice.exception;

import org.springframework.http.HttpStatus;

/** Thrown by the service layer whenever a request should map to a specific HTTP status + error code. */
public class ApiException extends RuntimeException {

    private final HttpStatus status;
    private final String code;
    private final Integer retryAfterSeconds;

    public ApiException(HttpStatus status, String code, String message) {
        this(status, code, message, null);
    }

    public ApiException(HttpStatus status, String code, String message, Integer retryAfterSeconds) {
        super(message);
        this.status = status;
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }

    public Integer getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
