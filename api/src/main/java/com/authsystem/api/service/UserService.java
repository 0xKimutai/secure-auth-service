package com.authsystem.api.service;

import com.authsystem.api.dto.auth.UserInfo;
import com.authsystem.api.entity.User;
import com.authsystem.api.exception.AuthenticationException;
import com.authsystem.api.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User findById(UUID id) {
        return userRepository.findById(id).orElseThrow(AuthenticationException::userNotFound);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(AuthenticationException::userNotFound);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(AuthenticationException::userNotFound);
    }

    public User findByMobile(String mobile) {
        return userRepository.findByMobile(mobile).orElseThrow(AuthenticationException::userNotFound);
    }

    public User findByUsernameOrEmailOrMobile(String identifier) {
        return userRepository.findByUsernameOrEmailOrMobile(identifier, identifier, identifier)
                .orElseThrow(AuthenticationException::userNotFound);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public boolean existsByMobile(String mobile) {
        return userRepository.existsByMobile(mobile);
    }

    // Create user without firstName/lastName
    public User createUser(String username, String email, String password, String mobile) {
        if (existsByUsername(username)) throw AuthenticationException.usernameAlreadyExists();
        if (existsByEmail(email)) throw AuthenticationException.emailAlreadyExists();
        if (mobile != null && existsByMobile(mobile)) throw AuthenticationException.mobileAlreadyExists();

        User user = new User(username, email, mobile);
        user.setPassword(password); // add hashing if needed
        user.setEnabled(true);

        return userRepository.save(user);
    }

    // Update user profile without firstName/lastName
    public User updateUserProfile(UUID userId, String mobile) {
        User user = findById(userId);
        user.setMobile(mobile);
        return userRepository.save(user);
    }

    public User updateUserEmail(UUID userId, String newEmail) {
        if (existsByEmail(newEmail)) throw AuthenticationException.emailAlreadyExists();
        User user = findById(userId);
        user.setEmail(newEmail);
        return userRepository.save(user);
    }

    public void validateUserAccountStatus(User user) {
        if (user == null || !user.getEnabled()) {
            throw new AuthenticationException("User account is disabled or does not exist");
        }
    }

    public void updateLastLogin(UUID userId) {
        User user = findById(userId);
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);
    }

    public UserInfo convertToUserInfo(User user) {
        return new UserInfo(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getMobile(),
                user.getEnabled(),
                user.getCreatedAt(),
                user.getLastLogin()
        );
    }

    public List<UserInfo> convertToUserInfoList(List<User> users) {
        return users.stream().map(this::convertToUserInfo).collect(Collectors.toList());
    }

    public List<UserInfo> getAllEnabledUsers() {
        return convertToUserInfoList(userRepository.findByEnabledTrue());
    }

    public List<UserInfo> getAllDisabledUsers() {
        return convertToUserInfoList(userRepository.findByEnabledFalse());
    }

    public List<UserInfo> getInactiveUsers(int days) {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(days);
        return convertToUserInfoList(userRepository.findInactiveUsers(cutoff));
    }

    public long getTotalEnabledUsers() {
        return userRepository.countEnabledUsers();
    }

    public void enableUser(UUID userId) {
        User user = findById(userId);
        user.setEnabled(true);
        userRepository.save(user);
    }

    public void disableUser(UUID userId) {
        User user = findById(userId);
        user.setEnabled(false);
        userRepository.save(user);
    }

    public void deleteUser(UUID userId) {
        User user = findById(userId);
        userRepository.delete(user);
    }

}
