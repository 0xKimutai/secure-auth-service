package com.kimutai.auth.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.kimutai.auth.dto.AuthResponse;
import com.kimutai.auth.dto.LoginRequest;
import com.kimutai.auth.dto.SignupRequest;
import com.kimutai.auth.entity.User;
import com.kimutai.auth.repo.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthResponse signup(SignupRequest req) {
        if (userRepository.existsByEmail(req.email())) {
            throw new IllegalArgumentException("Email already in use");
        }
        User saved = userRepository.save(
                User.builder()
                        .email(req.email())
                        .password(passwordEncoder.encode(req.password()))
                        .build()
        );
        String token = jwtService.generateToken(saved.getEmail());
        return new AuthResponse(saved.getEmail(), token);
    }

    public AuthResponse login(LoginRequest req) {
        User u = userRepository.findByEmail(req.email())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));
        if (!passwordEncoder.matches(req.password(), u.getPassword())) {
            throw new IllegalArgumentException("Invalid credentials");
        }
        String token = jwtService.generateToken(u.getEmail());
        return new AuthResponse(u.getEmail(), token);
    }
}
