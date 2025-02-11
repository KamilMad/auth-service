package com.kamil.auth_service.services;

import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service

public class AuthenticationService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final BCryptPasswordEncoder encoder;
    private final JwtService jwtService;


    public AuthenticationService(UserRepository userRepository, AuthenticationManager authenticationManager, BCryptPasswordEncoder encoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.encoder = encoder;
        this.jwtService = jwtService;
    }

    public User register(RegisterUserDto input) {

        User user = new User();
        user.setEmail(input.getEmail());
        user.setPassword(encoder.encode(input.getPassword()));

        return userRepository.save(user);
    }

    public String authenticate(LoginUserDto loginUserDto) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginUserDto.getEmail(),
                        loginUserDto.getPassword()
                        ));

        // Code below is redundant, because authenticationManager fetches user from db,
        // so if any error occurs it will be thrown there
        User authenticatedUser = userRepository.findByEmail(loginUserDto.getEmail()).orElseThrow(
                () -> new UsernameNotFoundException("User with email:" + loginUserDto.getEmail() + " not found in database")
        );

        return jwtService.generateToken(authenticatedUser.getEmail());
    }
}
