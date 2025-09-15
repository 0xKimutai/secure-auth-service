package com.authsystem.api.dto.auth;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonProperty;

public class LoginResponse {
    
    @JsonProperty("access_token")
    private String accessToken;
    
    @JsonProperty("token_type")
    private String tokenType = "Bearer";
    
    @JsonProperty("expires_in")
    private Long expiresIn; // Token expiration time in seconds
    
    @JsonProperty("refresh_token")
    private String refreshToken;
    
    @JsonProperty("user_info")
    private UserInfo userInfo;
    
    @JsonProperty("login_time")
    private LocalDateTime loginTime;
    
    // Default constructor
    public LoginResponse() {
        this.loginTime = LocalDateTime.now();
    }
    
    // Constructor with essential fields
    public LoginResponse(String accessToken, Long expiresIn, UserInfo userInfo) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.userInfo = userInfo;
        this.loginTime = LocalDateTime.now();
    }
    
    // Full constructor
    public LoginResponse(String accessToken, String tokenType, Long expiresIn, 
                        String refreshToken, UserInfo userInfo) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
        this.userInfo = userInfo;
        this.loginTime = LocalDateTime.now();
    }
    
    // Getters and Setters
    public String getAccessToken() {
        return accessToken;
    }
    
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
    
    public String getTokenType() {
        return tokenType;
    }
    
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
    
    public Long getExpiresIn() {
        return expiresIn;
    }
    
    public void setExpiresIn(Long expiresIn) {
        this.expiresIn = expiresIn;
    }
    
    public String getRefreshToken() {
        return refreshToken;
    }
    
    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
    
    public UserInfo getUserInfo() {
        return userInfo;
    }
    
    public void setUserInfo(UserInfo userInfo) {
        this.userInfo = userInfo;
    }
    
    public LocalDateTime getLoginTime() {
        return loginTime;
    }
    
    public void setLoginTime(LocalDateTime loginTime) {
        this.loginTime = loginTime;
    }
    
    // toString (excluding tokens for security)
    @Override
    public String toString() {
        return "LoginResponse{" +
                "tokenType='" + tokenType + '\'' +
                ", expiresIn=" + expiresIn +
                ", userInfo=" + userInfo +
                ", loginTime=" + loginTime +
                '}';
    }
}