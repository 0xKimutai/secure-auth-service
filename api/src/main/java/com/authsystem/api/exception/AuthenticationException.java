package com.authsystem.api.exception;

import org.springframework.http.HttpStatus;

/**
 * Custom AuthenticationException for handling authentication/authorization errors.
 * Provides static factory methods for common error cases to keep service code clean.
 */
public class AuthenticationException extends RuntimeException {

    private final HttpStatus httpStatus;
    private final String errorCode;

    // Default constructor
    public AuthenticationException(String message) {
        super(message);
        this.httpStatus = HttpStatus.UNAUTHORIZED;
        this.errorCode = "AUTH_ERROR";
    }

    // Constructor with HTTP status
    public AuthenticationException(String message, HttpStatus httpStatus) {
        super(message);
        this.httpStatus = httpStatus;
        this.errorCode = "AUTH_ERROR";
    }

    // Constructor with error code
    public AuthenticationException(String message, String errorCode) {
        super(message);
        this.httpStatus = HttpStatus.UNAUTHORIZED;
        this.errorCode = errorCode;
    }

    // Full constructor
    public AuthenticationException(String message, HttpStatus httpStatus, String errorCode) {
        super(message);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
    }

    // Constructor with cause (for wrapping other exceptions)
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
        this.httpStatus = HttpStatus.UNAUTHORIZED;
        this.errorCode = "AUTH_ERROR";
    }

    // Full constructor with cause
    public AuthenticationException(String message, Throwable cause, HttpStatus httpStatus, String errorCode) {
        super(message, cause);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
    }

    // 🔹 Static factory methods for common errors
    public static AuthenticationException invalidCredentials() {
        return new AuthenticationException(
                "Invalid username or password",
                HttpStatus.UNAUTHORIZED,
                "INVALID_CREDENTIALS"
        );
    }

    public static AuthenticationException invalidRequest(String message) {
        return new AuthenticationException(
                message,
                HttpStatus.BAD_REQUEST,
                "INVALID_REQUEST"
        );
    }

    public static AuthenticationException tokenExpired() {
        return new AuthenticationException(
                "Authentication token has expired",
                HttpStatus.UNAUTHORIZED,
                "TOKEN_EXPIRED"
        );
    }

    public static AuthenticationException tokenInvalid() {
        return new AuthenticationException(
                "Invalid authentication token",
                HttpStatus.UNAUTHORIZED,
                "TOKEN_INVALID"
        );
    }

    public static AuthenticationException tokenMissing() {
        return new AuthenticationException(
                "Authentication token is required",
                HttpStatus.UNAUTHORIZED,
                "TOKEN_MISSING"
        );
    }

    public static AuthenticationException accountDisabled() {
        return new AuthenticationException(
                "User account is disabled",
                HttpStatus.FORBIDDEN,
                "ACCOUNT_DISABLED"
        );
    }

    public static AuthenticationException accountLocked() {
        return new AuthenticationException(
                "User account is locked",
                HttpStatus.FORBIDDEN,
                "ACCOUNT_LOCKED"
        );
    }

    public static AuthenticationException accountExpired() {
        return new AuthenticationException(
                "User account has expired",
                HttpStatus.FORBIDDEN,
                "ACCOUNT_EXPIRED"
        );
    }

    public static AuthenticationException credentialsExpired() {
        return new AuthenticationException(
                "User credentials have expired",
                HttpStatus.FORBIDDEN,
                "CREDENTIALS_EXPIRED"
        );
    }

    public static AuthenticationException userNotFound() {
        return new AuthenticationException(
                "User not found",
                HttpStatus.NOT_FOUND,
                "USER_NOT_FOUND"
        );
    }

    public static AuthenticationException userAlreadyExists() {
        return new AuthenticationException(
                "User already exists",
                HttpStatus.CONFLICT,
                "USER_ALREADY_EXISTS"
        );
    }

    public static AuthenticationException emailAlreadyExists() {
        return new AuthenticationException(
                "Email address is already registered",
                HttpStatus.CONFLICT,
                "EMAIL_ALREADY_EXISTS"
        );
    }

    public static AuthenticationException usernameAlreadyExists() {
        return new AuthenticationException(
                "Username is already taken",
                HttpStatus.CONFLICT,
                "USERNAME_ALREADY_EXISTS"
        );
    }

    public static AuthenticationException mobileAlreadyExists() {
        return new AuthenticationException(
                "Mobile number is already registered",
                HttpStatus.CONFLICT,
                "MOBILE_ALREADY_EXISTS"
        );
    }

    public static AuthenticationException insufficientPermissions() {
        return new AuthenticationException(
                "Insufficient permissions to access this resource",
                HttpStatus.FORBIDDEN,
                "INSUFFICIENT_PERMISSIONS"
        );
    }

    // 🔹 Getters
    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public int getStatusCode() {
        return httpStatus.value();
    }

    @Override
    public String toString() {
        return "AuthenticationException{" +
                "message='" + getMessage() + '\'' +
                ", httpStatus=" + httpStatus +
                ", errorCode='" + errorCode + '\'' +
                '}';
    }
}
