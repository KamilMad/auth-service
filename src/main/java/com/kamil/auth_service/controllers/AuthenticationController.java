package com.kamil.auth_service.controllers;

import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.services.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public ResponseEntity<User> registerUser(@RequestBody RegisterUserDto registerUserDto) {
        User registeredUser = authenticationService.singUp(registerUserDto);

        return ResponseEntity.ok(registeredUser);
    }
}
