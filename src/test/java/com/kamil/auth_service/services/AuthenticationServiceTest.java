package com.kamil.auth_service.services;

import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private BCryptPasswordEncoder encoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthenticationService authenticationService;


    @Test
    void shouldRegisterNewUser() {
        // Arrange
        RegisterUserDto dto = new RegisterUserDto();
        dto.setEmail("test@example.com");
        dto.setPassword("password123");

        String dummyEncodedPassword = "$2a$10$VvZGG9s9bbUem.KQwM3R3eI.RndT1ZZgXU3yXny0nTQpeA5O0JygO";
        Mockito.when(encoder.encode(dto.getPassword())).thenReturn(dummyEncodedPassword);

        User mockUser = new User();
        mockUser.setEmail("test@example.com");
        mockUser.setPassword(dummyEncodedPassword);
        Mockito.when(userRepository.save(Mockito.any(User.class))).thenReturn(mockUser);

        // Act
        User result = authenticationService.register(dto);

        // Assert
        assertNotNull(result);
        assertEquals(dto.getEmail(), result.getEmail());
        assertEquals(dummyEncodedPassword, result.getPassword());

        Mockito.verify(encoder).encode("password123");
        Mockito.verify(userRepository).save(Mockito.any(User.class));
    }
}
