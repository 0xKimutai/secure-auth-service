package com.authsystem.api.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class LoginRequest {

    @NotBlank(message = "Username, email, or mobile is required")
    private String usernameOrEmailOrMobile;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
    private String password;

    public LoginRequest() {}

    public LoginRequest(String usernameOrEmailOrMobile, String password) {
        this.usernameOrEmailOrMobile = usernameOrEmailOrMobile;
        this.password = password;
    }

    public String getUsernameOrEmailOrMobile() { return usernameOrEmailOrMobile; }
    public void setUsernameOrEmailOrMobile(String usernameOrEmailOrMobile) {
        this.usernameOrEmailOrMobile = usernameOrEmailOrMobile;
    }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    @Override
    public String toString() {
        return "LoginRequest{" +
                "usernameOrEmailOrMobile='" + usernameOrEmailOrMobile + '\'' +
                ", password='[PROTECTED]'" +
                '}';
    }
}
