package com.kamil.auth_service.controllers;

import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginResponse;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.services.AuthenticationService;
import com.kamil.auth_service.services.JwtService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequestMapping("/auth")
@RestController
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;

    public AuthenticationController(AuthenticationService authenticationService, JwtService jwtService) {
        this.authenticationService = authenticationService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> registerUser(@Valid @RequestBody RegisterUserDto registerUserDto) {
        User registeredUser = authenticationService.register(registerUserDto);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticate(@Valid @RequestBody LoginUserDto loginUserDto) {
        String token = authenticationService.authenticate(loginUserDto);
        long expiresIn = jwtService.getExpirationTime();

        return ResponseEntity.ok(new LoginResponse(token, expiresIn));
    }
}
