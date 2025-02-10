package com.kamil.auth_service.services;

import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.Optional;

@SpringBootTest
@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceTest {

    @MockitoBean
    private UserRepository userRepository;
    @MockitoBean
    private AuthenticationManager authenticationManager;
    @MockitoBean
    private BCryptPasswordEncoder encoder;
    @MockitoBean
    private JwtService jwtService;

    @Autowired
    private AuthenticationService authenticationService;

    @Test
    void shouldRegisterNewUser() {
        RegisterUserDto dto = new RegisterUserDto();
        dto.setEmail("test@example.com");
        dto.setPassword("password123");

        User user

        Mockito.when(userRepository.findByEmail(dto.getEmail())).thenReturn(Optional.of())

        authenticationService.singUp(dto);

        Mockito.verify(userRepository).findByEmail(dto.getEmail());
    }


}
