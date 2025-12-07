package com.company.jwtdemo.service;

import com.company.jwtdemo.DTO.AuthResponse;
import com.company.jwtdemo.DTO.RegisterRequest;
import com.company.jwtdemo.entity.User;
import com.company.jwtdemo.repo.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    @Transactional
    public AuthResponse register(RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.username())) {
            throw new RuntimeException("Username already exists");
        }

        User user = new User();
        user.setUsername(registerRequest.username());
        user.setPassword(passwordEncoder.encode(registerRequest.password()));
        user.setRole("ROLE_USER");

        userRepository.save(user);

        return new AuthResponse(null, user.getUsername());
    }


}
