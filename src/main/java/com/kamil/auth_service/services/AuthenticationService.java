package com.kamil.auth_service.services;

import com.kamil.auth_service.exception.UserAlreadyExistsException;
import com.kamil.auth_service.model.Role;
import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

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
        String email = normalizeEmail(input.getEmail());

        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException("User with that email already exists.");
        }

        User user = createUser(email, input.getPassword())

        return userRepository.save(user);
    }

    public String authenticate(LoginUserDto loginUserDto) {
        String email = normalizeEmail(loginUserDto.getEmail());

        authenticateUser(email, loginUserDto.getPassword());

        User authenticatedUser = findUserByEmail(email);

        return generateTokenForUser(authenticatedUser);
    }

    private User createUser(String email, String password) {
        return User.builder()
                .email(email)
                .password(encoder.encode(password))
                .roles(assignRole())
                .build();

    }

    private Set<Role> assignRole() {
        return userRepository.count() == 0 ? Set.of(Role.ADMIN) : Set.of(Role.USER);
    }

    private void authenticateUser(String email, String password) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password));
        } catch (AuthenticationException ex) {
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    private String normalizeEmail(String email) {
        return email.toLowerCase();
    }

    private String generateTokenForUser(User user) {
        return jwtService.generateToken(user.getEmail());
    }

    private User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
    }
}
