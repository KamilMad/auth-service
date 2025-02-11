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

    private final String TEST_EMAIL = "test@example.com";
    private final String TEST_PASSWORD = "password123";
    private final String ENCODED_PASSWORD = "$2a$10$VvZGG9s9bbUem.KQwM3R3eI.RndT1ZZgXU3yXny0nTQpeA5O0JygO";

    @Test
    void shouldRegisterNewUser() {
        // Arrange
        RegisterUserDto dto = crateRegisterUserDto(TEST_EMAIL, TEST_PASSWORD);

        Mockito.when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(false);
        Mockito.when(encoder.encode(dto.getPassword())).thenReturn(ENCODED_PASSWORD);
        User mockUser = createUser(TEST_EMAIL, ENCODED_PASSWORD);
        Mockito.when(userRepository.save(Mockito.any(User.class))).thenReturn(mockUser);

        // Act
        User result = authenticationService.register(dto);

        // Assert
        assertNotNull(result);
        assertEquals(dto.getEmail(), result.getEmail());
        assertEquals(ENCODED_PASSWORD, result.getPassword());

        Mockito.verify(encoder).encode("password123");
        Mockito.verify(userRepository).save(Mockito.any(User.class));
    }

    private RegisterUserDto crateRegisterUserDto(String email, String password) {
        RegisterUserDto dto = new RegisterUserDto();
        dto.setEmail(email);
        dto.setPassword(password);

        return dto;
    }

    private User createUser(String email, String password) {
        User mockUser = new User();
        mockUser.setEmail(email);
        mockUser.setPassword(password);

        return mockUser;
    }

}
