package com.authsystem.api.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authsystem.api.dto.auth.LoginResponse;
import com.authsystem.api.dto.auth.SignupRequest;
import com.authsystem.api.dto.auth.SignupResponse;
import com.authsystem.api.dto.auth.UserInfo;
import com.authsystem.api.dto.common.ApiResponse;
import com.authsystem.api.service.AuthService;
import com.authsystem.api.service.KeycloakAdminService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = "http://localhost:5000", maxAge = 3600)
public class AuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    
    private final AuthService authService;
    private final KeycloakAdminService keycloakAdminService;
    
    @Autowired
    public AuthController(AuthService authService, KeycloakAdminService keycloakAdminService) {
        this.authService = authService;
        this.keycloakAdminService = keycloakAdminService;
    }
    
    /**
     * User signup/registration endpoint
     * Supports username, email, and mobile
     */
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<SignupResponse>> signup(@Valid @RequestBody SignupRequest request) {
        logger.info("Signup request received for identifier: {}", 
                    request.getUsername() != null ? request.getUsername() : request.getEmail());

        try {
            // Process signup in backend
            SignupResponse response = authService.processSignup(request);

            // Call Keycloak Admin API to create the user in Keycloak
            keycloakAdminService.createUser(
                response.getUserInfo().getUsername(),
                response.getUserInfo().getEmail(),
                request.getPassword(), // use the password from the request
                response.getUserInfo().getMobile()
            );

            ApiResponse<SignupResponse> apiResponse = ApiResponse.success(
                "Account created successfully", 
                response
            );

            return new ResponseEntity<>(apiResponse, HttpStatus.CREATED);

        } catch (Exception e) {
            logger.error("Signup failed for identifier: {}", 
                        request.getUsername() != null ? request.getUsername() : request.getEmail(), e);
            throw e; // Let GlobalExceptionHandler handle it
        }
    }

    
    /**
     * Process Keycloak login (token validation and user sync)
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> processLogin(Authentication authentication) {
        logger.info("Processing login for authenticated user");
        
        try {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            String accessToken = jwt.getTokenValue();
            
            LoginResponse response = authService.processKeycloakLogin(accessToken);
            
            ApiResponse<LoginResponse> apiResponse = ApiResponse.success(
                "Login successful", 
                response
            );
            
            return ResponseEntity.ok(apiResponse);
            
        } catch (Exception e) {
            logger.error("Login processing failed", e);
            throw e;
        }
    }
    
    @PostMapping("/login/token")
    public ResponseEntity<ApiResponse<LoginResponse>> processLoginWithToken(@RequestBody TokenRequest request) {
        logger.info("Processing login with provided token or identifier");
        
        try {
            LoginResponse response = authService.processKeycloakLogin(request.getToken());
            
            ApiResponse<LoginResponse> apiResponse = ApiResponse.success(
                "Login successful", 
                response
            );
            
            return ResponseEntity.ok(apiResponse);
            
        } catch (Exception e) {
            logger.error("Token-based login failed", e);
            throw e;
        }
    }
    
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(Authentication authentication) {
        logger.info("Logout request received");
        
        try {
            if (authentication != null) {
                Jwt jwt = (Jwt) authentication.getPrincipal();
                String accessToken = jwt.getTokenValue();
                authService.logout(accessToken);
            }
            
            ApiResponse<String> response = ApiResponse.success("Logged out successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.warn("Logout processing failed", e);
            ApiResponse<String> response = ApiResponse.success("Logged out successfully");
            return ResponseEntity.ok(response);
        }
    }
    
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserInfo>> getCurrentUser(Authentication authentication) {
        logger.debug("Getting current user info");
        
        try {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            String accessToken = jwt.getTokenValue();
            
            UserInfo userInfo = authService.getCurrentUserInfo(accessToken);
            
            ApiResponse<UserInfo> response = ApiResponse.success(
                "User information retrieved successfully", 
                userInfo
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Failed to get current user info", e);
            throw e;
        }
    }
    
    @PostMapping("/validate")
    public ResponseEntity<ApiResponse<UserInfo>> validateToken(@RequestBody TokenRequest request) {
        logger.debug("Token validation request received");
        
        try {
            UserInfo userInfo = authService.validateToken(request.getToken());
            
            ApiResponse<UserInfo> response = ApiResponse.success(
                "Token is valid", 
                userInfo
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.warn("Token validation failed", e);
            throw e;
        }
    }
    
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<LoginResponse>> refreshToken(@RequestBody RefreshTokenRequest request) {
        logger.info("Token refresh request received");
        
        try {
            LoginResponse response = authService.refreshToken(request.getRefreshToken());
            
            ApiResponse<LoginResponse> apiResponse = ApiResponse.success(
                "Token refreshed successfully", 
                response
            );
            
            return ResponseEntity.ok(apiResponse);
            
        } catch (Exception e) {
            logger.error("Token refresh failed", e);
            throw e;
        }
    }
    
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> healthCheck() {
        logger.debug("Auth service health check");
        
        ApiResponse<String> response = ApiResponse.success(
            "Authentication service is healthy",
            "UP"
        );
        
        return ResponseEntity.ok(response);
    }
    
    // Inner classes for request DTOs
    public static class TokenRequest {
        private String token;
        
        public TokenRequest() {}
        public TokenRequest(String token) { this.token = token; }
        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }
    
    public static class RefreshTokenRequest {
        private String refreshToken;
        
        public RefreshTokenRequest() {}
        public RefreshTokenRequest(String refreshToken) { this.refreshToken = refreshToken; }
        public String getRefreshToken() { return refreshToken; }
        public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    }
}
