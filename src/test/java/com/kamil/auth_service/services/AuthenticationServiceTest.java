package com.kamil.auth_service.services;

import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Optional;

@SpringBootTest
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
        // Given
        RegisterUserDto dto = new RegisterUserDto();
        dto.setEmail("test@example.com");
        dto.setPassword("password123");

        String dummyEncodedPassword = "$2a$10$VvZGG9s9bbUem.KQwM3R3eI.RndT1ZZgXU3yXny0nTQpeA5O0JygO";
        Mockito.when(encoder.encode(dto.getPassword())).thenReturn(dummyEncodedPassword);

        User mockUser = new User();
        mockUser.setEmail("test@example.com");
        mockUser.setPassword(dummyEncodedPassword);
        Mockito.when(userRepository.save(Mockito.any(User.class))).thenReturn(mockUser);

        // When
        User result = authenticationService.singUp(dto);

        // Then
        assertNotNull(result);
        assertEquals(dto.getEmail(), result.getEmail());
        assertEquals(dummyEncodedPassword, result.getPassword());

        Mockito.verify(encoder).encode("password123");
        Mockito.verify(userRepository).save(Mockito.any(User.class));
    }
}
