package com.kamil.auth_service.services;

import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service

public class AuthenticationService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;


    public AuthenticationService(UserRepository userRepository, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
    }

    public User singUp(RegisterUserDto input) {
        User user = new User();
        user.setEmail(input.getEmail());
        user.setPassword(input.getPassword());

        return userRepository.save(user);
    }

    public User authenticate(LoginUserDto input) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getEmail(),
                        input.getPassword()
                        )
        );

        return userRepository.findByEmail(input.getEmail()).orElseThrow();
    }
}
