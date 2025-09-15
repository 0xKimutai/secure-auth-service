package com.authsystem.api.controller;

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.authsystem.api.dto.auth.UserInfo;
import com.authsystem.api.dto.common.ApiResponse;
import com.authsystem.api.entity.User;
import com.authsystem.api.service.UserService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@RestController
@RequestMapping("/api/v1/users")
@CrossOrigin(origins = "*", maxAge = 3600)
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/lookup/{identifier}")
    @PreAuthorize("hasRole('ADMIN') or @userController.isCurrentUser(authentication, #identifier)")
    public ResponseEntity<ApiResponse<UserInfo>> getUserByIdentifier(@PathVariable String identifier) {
        logger.debug("Looking up user by identifier: {}", identifier);

        User user;
        try {
            UUID id = UUID.fromString(identifier);
            user = userService.findById(id);
        } catch (IllegalArgumentException e) {
            user = userService.findByUsernameOrEmailOrMobile(identifier);
        }

        UserInfo userInfo = userService.convertToUserInfo(user);
        return ResponseEntity.ok(ApiResponse.success("User found successfully", userInfo));
    }

    @PutMapping("/{id}/profile")
    @PreAuthorize("hasRole('ADMIN') or @userController.isCurrentUser(authentication, #id)")
    public ResponseEntity<ApiResponse<UserInfo>> updateProfile(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateProfileRequest request) {

        logger.info("Updating profile for user ID: {}", id);

        User updatedUser = userService.updateUserProfile(id, request.getMobile());

        UserInfo userInfo = userService.convertToUserInfo(updatedUser);
        return ResponseEntity.ok(ApiResponse.success("Profile updated successfully", userInfo));
    }

    @PutMapping("/{id}/email")
    @PreAuthorize("hasRole('ADMIN') or @userController.isCurrentUser(authentication, #id)")
    public ResponseEntity<ApiResponse<UserInfo>> updateEmail(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateEmailRequest request) {

        logger.info("Updating email for user ID: {}", id);

        User updatedUser = userService.updateUserEmail(id, request.getEmail());
        UserInfo userInfo = userService.convertToUserInfo(updatedUser);
        return ResponseEntity.ok(ApiResponse.success("Email updated successfully", userInfo));
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserInfo>>> getAllUsers() {
        logger.debug("Getting all enabled users");

        List<UserInfo> userInfoList = userService.getAllEnabledUsers();

        ApiResponse<List<UserInfo>> response = ApiResponse.success(
                "Users retrieved successfully",
                userInfoList
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/disabled")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserInfo>>> getDisabledUsers() {
        logger.debug("Getting all disabled users");

        List<UserInfo> userInfoList = userService.getAllDisabledUsers();

        ApiResponse<List<UserInfo>> response = ApiResponse.success(
                "Disabled users retrieved successfully",
                userInfoList
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/inactive")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserInfo>>> getInactiveUsers(
            @RequestParam(name = "days", defaultValue = "30") int days) {

        logger.debug("Getting users inactive for {} days", days);

        List<UserInfo> userInfoList = userService.getInactiveUsers(days);

        ApiResponse<List<UserInfo>> response = ApiResponse.success(
                String.format("Found %d users inactive for %d days", userInfoList.size(), days),
                userInfoList
        );

        return ResponseEntity.ok(response);
    }

    @PutMapping("/{id}/enable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserInfo>> enableUser(@PathVariable UUID id) {
        logger.info("Enabling user account: {}", id);

        userService.enableUser(id);
        User user = userService.findById(id);
        UserInfo userInfo = userService.convertToUserInfo(user);

        return ResponseEntity.ok(ApiResponse.success("User account enabled successfully", userInfo));
    }

    @PutMapping("/{id}/disable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserInfo>> disableUser(@PathVariable UUID id) {
        logger.info("Disabling user account: {}", id);

        userService.disableUser(id);
        User user = userService.findById(id);
        UserInfo userInfo = userService.convertToUserInfo(user);

        return ResponseEntity.ok(ApiResponse.success("User account disabled successfully", userInfo));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> deleteUser(@PathVariable UUID id) {
        logger.info("Deleting user: {}", id);

        userService.deleteUser(id);

        return ResponseEntity.ok(ApiResponse.success("User deleted successfully", "User account has been removed"));
    }

    @GetMapping("/stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserStats>> getUserStats() {
        logger.debug("Getting user statistics");

        long totalEnabled = userService.getTotalEnabledUsers();
        long totalDisabled = userService.getAllDisabledUsers().size();
        long totalInactive30Days = userService.getInactiveUsers(30).size();
        long totalInactive7Days = userService.getInactiveUsers(7).size();

        UserStats stats = new UserStats(
                totalEnabled,
                totalDisabled,
                totalEnabled + totalDisabled,
                totalInactive7Days,
                totalInactive30Days
        );

        return ResponseEntity.ok(ApiResponse.success("User statistics retrieved successfully", stats));
    }

    public boolean isCurrentUser(Authentication authentication, UUID userId) {
        try {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            String currentUsername = jwt.getClaimAsString("preferred_username");

            User currentUser = userService.findByUsername(currentUsername);
            return currentUser.getId().equals(userId);

        } catch (Exception e) {
            logger.warn("Error checking if user is current user", e);
            return false;
        }
    }

    public boolean isCurrentUser(Authentication authentication, String identifier) {
        try {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            String currentUsername = jwt.getClaimAsString("preferred_username");

            return currentUsername.equals(identifier);
        } catch (Exception e) {
            logger.warn("Error checking if user is current user", e);
            return false;
        }
    }

    // Request DTOs
    public static class UpdateProfileRequest {
        @Size(max = 15, message = "Mobile number cannot exceed 15 characters")
        private String mobile;

        public UpdateProfileRequest() {}
        public UpdateProfileRequest(String mobile) { this.mobile = mobile; }

        public String getMobile() { return mobile; }
        public void setMobile(String mobile) { this.mobile = mobile; }
    }

    public static class UpdateEmailRequest {
        @NotBlank(message = "Email is required")
        @Email(message = "Please provide a valid email address")
        @Size(max = 100, message = "Email cannot exceed 100 characters")
        private String email;

        public UpdateEmailRequest() {}
        public UpdateEmailRequest(String email) { this.email = email; }

        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }

    public static class UserStats {
        private long totalEnabledUsers;
        private long totalDisabledUsers;
        private long totalUsers;
        private long inactiveUsers7Days;
        private long inactiveUsers30Days;

        public UserStats() {}

        public UserStats(long totalEnabledUsers, long totalDisabledUsers, long totalUsers,
                         long inactiveUsers7Days, long inactiveUsers30Days) {
            this.totalEnabledUsers = totalEnabledUsers;
            this.totalDisabledUsers = totalDisabledUsers;
            this.totalUsers = totalUsers;
            this.inactiveUsers7Days = inactiveUsers7Days;
            this.inactiveUsers30Days = inactiveUsers30Days;
        }

        public long getTotalEnabledUsers() { return totalEnabledUsers; }
        public void setTotalEnabledUsers(long totalEnabledUsers) { this.totalEnabledUsers = totalEnabledUsers; }

        public long getTotalDisabledUsers() { return totalDisabledUsers; }
        public void setTotalDisabledUsers(long totalDisabledUsers) { this.totalDisabledUsers = totalDisabledUsers; }

        public long getTotalUsers() { return totalUsers; }
        public void setTotalUsers(long totalUsers) { this.totalUsers = totalUsers; }

        public long getInactiveUsers7Days() { return inactiveUsers7Days; }
        public void setInactiveUsers7Days(long inactiveUsers7Days) { this.inactiveUsers7Days = inactiveUsers7Days; }

        public long getInactiveUsers30Days() { return inactiveUsers30Days; }
        public void setInactiveUsers30Days(long inactiveUsers30Days) { this.inactiveUsers30Days = inactiveUsers30Days; }
    }
}
