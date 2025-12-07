package com.company.jwtdemo.controller;

import com.company.jwtdemo.DTO.AuthResponse;
import com.company.jwtdemo.DTO.LoginRequest;
import com.company.jwtdemo.DTO.RegisterRequest;
import com.company.jwtdemo.service.AuthService;
import com.company.jwtdemo.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class AuthController {

    Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;
    private final AuthService authService;
    private final AuthenticationManager authenticationManager;

    public AuthController(TokenService tokenService, AuthService authService, AuthenticationManager authenticationManager) {
        this.tokenService = tokenService;
        this.authService = authService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public AuthResponse register(@RequestBody RegisterRequest registerRequest) throws Exception {
        return authService.register(registerRequest);
    }



    @PostMapping("/token")
    public AuthResponse token(
            @RequestBody LoginRequest  loginRequest
    ){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.username(),
                        loginRequest.password()
                )
        );
        String token = tokenService.generateToken(authentication);
        return new AuthResponse(token, authentication.getName());
    }
}
