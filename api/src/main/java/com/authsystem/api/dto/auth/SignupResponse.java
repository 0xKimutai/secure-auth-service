package com.authsystem.api.dto.auth;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SignupResponse {
    
    @JsonProperty("user_info")
    private UserInfo userInfo;
    
    @JsonProperty("message")
    private String message;
    
    @JsonProperty("account_status")
    private String accountStatus; // "PENDING_VERIFICATION", "ACTIVE", "INACTIVE"
    
    @JsonProperty("verification_required")
    private boolean verificationRequired;
    
    @JsonProperty("verification_email_sent")
    private boolean verificationEmailSent;
    
    @JsonProperty("signup_time")
    private LocalDateTime signupTime;
    
    @JsonProperty("next_steps")
    private String nextSteps;
    
    // Default constructor
    public SignupResponse() {
        this.signupTime = LocalDateTime.now();
    }
    
    // Constructor with essential fields
    public SignupResponse(UserInfo userInfo, String message) {
        this.userInfo = userInfo;
        this.message = message;
        this.signupTime = LocalDateTime.now();
        this.accountStatus = "ACTIVE";
        this.verificationRequired = false;
    }
    
    // Constructor for pending verification
    public SignupResponse(UserInfo userInfo, String message, boolean verificationRequired, 
                         boolean verificationEmailSent, String nextSteps) {
        this.userInfo = userInfo;
        this.message = message;
        this.accountStatus = verificationRequired ? "PENDING_VERIFICATION" : "ACTIVE";
        this.verificationRequired = verificationRequired;
        this.verificationEmailSent = verificationEmailSent;
        this.nextSteps = nextSteps;
        this.signupTime = LocalDateTime.now();
    }
    
    // Full constructor
    public SignupResponse(UserInfo userInfo, String message, String accountStatus,
                         boolean verificationRequired, boolean verificationEmailSent,
                         String nextSteps) {
        this.userInfo = userInfo;
        this.message = message;
        this.accountStatus = accountStatus;
        this.verificationRequired = verificationRequired;
        this.verificationEmailSent = verificationEmailSent;
        this.nextSteps = nextSteps;
        this.signupTime = LocalDateTime.now();
    }
    
    // Static factory methods for common scenarios
    public static SignupResponse success(UserInfo userInfo) {
        return new SignupResponse(userInfo, "Account created successfully");
    }
    
    public static SignupResponse pendingVerification(UserInfo userInfo, boolean emailSent) {
        String nextSteps = emailSent ? 
            "Please check your email and click the verification link to activate your account." :
            "Please contact support to complete account verification.";
            
        return new SignupResponse(
            userInfo, 
            "Account created. Email verification required.",
            true,
            emailSent,
            nextSteps
        );
    }
    
    public static SignupResponse withCustomMessage(UserInfo userInfo, String message, String nextSteps) {
        SignupResponse response = new SignupResponse(userInfo, message);
        response.setNextSteps(nextSteps);
        return response;
    }
    
    // Getters and Setters
    public UserInfo getUserInfo() {
        return userInfo;
    }
    
    public void setUserInfo(UserInfo userInfo) {
        this.userInfo = userInfo;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public String getAccountStatus() {
        return accountStatus;
    }
    
    public void setAccountStatus(String accountStatus) {
        this.accountStatus = accountStatus;
    }
    
    public boolean isVerificationRequired() {
        return verificationRequired;
    }
    
    public void setVerificationRequired(boolean verificationRequired) {
        this.verificationRequired = verificationRequired;
    }
    
    public boolean isVerificationEmailSent() {
        return verificationEmailSent;
    }
    
    public void setVerificationEmailSent(boolean verificationEmailSent) {
        this.verificationEmailSent = verificationEmailSent;
    }
    
    public LocalDateTime getSignupTime() {
        return signupTime;
    }
    
    public void setSignupTime(LocalDateTime signupTime) {
        this.signupTime = signupTime;
    }
    
    public String getNextSteps() {
        return nextSteps;
    }
    
    public void setNextSteps(String nextSteps) {
        this.nextSteps = nextSteps;
    }
    
    @Override
    public String toString() {
        return "SignupResponse{" +
                "userInfo=" + userInfo +
                ", message='" + message + '\'' +
                ", accountStatus='" + accountStatus + '\'' +
                ", verificationRequired=" + verificationRequired +
                ", signupTime=" + signupTime +
                '}';
    }
}