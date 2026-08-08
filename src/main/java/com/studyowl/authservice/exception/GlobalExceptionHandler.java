package com.studyowl.authservice.exception;

import com.studyowl.authservice.dto.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CodeMismatchException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ExpiredCodeException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InvalidParameterException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InvalidPasswordException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.LimitExceededException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.NotAuthorizedException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.TooManyRequestsException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotConfirmedException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UsernameExistsException;

/**
 * Translates both our own ApiException and raw Cognito SDK exceptions into the
 * ErrorResponse shape declared in docs/openapi.yaml. Without this, a Cognito
 * exception would otherwise leak as a raw 500 with an AWS-internal message.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handleApiException(ApiException e) {
        return ResponseEntity.status(e.getStatus())
                .body(new ErrorResponse(e.getCode(), e.getMessage(), e.getRetryAfterSeconds()));
    }

    /**
     * X-User-Sub missing means this request reached auth-service without going through
     * Kong (or Kong's jwt plugin somehow let an unauthenticated request through) — see
     * AuthController's class doc. 401, not 400: this is an auth failure, not a
     * malformed request.
     */
    @ExceptionHandler(MissingRequestHeaderException.class)
    public ResponseEntity<ErrorResponse> handleMissingUserSub(MissingRequestHeaderException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse("UNAUTHENTICATED", "Missing or invalid credentials"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException e) {
        String message = e.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .orElse("Invalid request");
        return ResponseEntity.badRequest().body(new ErrorResponse("VALIDATION_ERROR", message));
    }

    @ExceptionHandler(CodeMismatchException.class)
    public ResponseEntity<ErrorResponse> handleCodeMismatch(CodeMismatchException e) {
        return ResponseEntity.badRequest().body(new ErrorResponse("INVALID_OTP", "Incorrect code"));
    }

    @ExceptionHandler(ExpiredCodeException.class)
    public ResponseEntity<ErrorResponse> handleExpiredCode(ExpiredCodeException e) {
        return ResponseEntity.badRequest().body(new ErrorResponse("OTP_EXPIRED", "Code expired, request a new one"));
    }

    @ExceptionHandler(UserNotConfirmedException.class)
    public ResponseEntity<ErrorResponse> handleUserNotConfirmed(UserNotConfirmedException e) {
        return ResponseEntity.badRequest().body(new ErrorResponse("USER_NOT_CONFIRMED", "Phone number not yet verified"));
    }

    @ExceptionHandler(UsernameExistsException.class)
    public ResponseEntity<ErrorResponse> handleUsernameExists(UsernameExistsException e) {
        // Surfaces only if two request-otp calls for the same brand-new number race each other.
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ErrorResponse("ALREADY_IN_PROGRESS", "A code was already requested for this number, try again shortly"));
    }

    @ExceptionHandler(NotAuthorizedException.class)
    public ResponseEntity<ErrorResponse> handleNotAuthorized(NotAuthorizedException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse("NOT_AUTHORIZED", "Invalid or expired credentials"));
    }

    @ExceptionHandler({TooManyRequestsException.class, LimitExceededException.class})
    public ResponseEntity<ErrorResponse> handleCognitoRateLimit(CognitoIdentityProviderException e) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(new ErrorResponse("RATE_LIMITED", "Too many attempts, try again later", 3600));
    }

    @ExceptionHandler({InvalidPasswordException.class, InvalidParameterException.class})
    public ResponseEntity<ErrorResponse> handleInvalidParameter(CognitoIdentityProviderException e) {
        return ResponseEntity.badRequest().body(new ErrorResponse("INVALID_REQUEST", e.getMessage()));
    }

    @ExceptionHandler(CognitoIdentityProviderException.class)
    public ResponseEntity<ErrorResponse> handleCognitoFallback(CognitoIdentityProviderException e) {
        log.error("Unhandled Cognito exception", e);
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                .body(new ErrorResponse("UPSTREAM_ERROR", "Authentication provider error, try again"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception e) {
        log.error("Unhandled exception", e);
        return ResponseEntity.internalServerError()
                .body(new ErrorResponse("INTERNAL_ERROR", "Something went wrong"));
    }
}
