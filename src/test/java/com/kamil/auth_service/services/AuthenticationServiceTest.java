package com.kamil.auth_service.services;

import com.kamil.auth_service.exception.UserAlreadyExistsException;
import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

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

    @Test
    void shouldThrowExceptionWhenUserAlreadyExist() {
        RegisterUserDto dto = crateRegisterUserDto(TEST_EMAIL, TEST_PASSWORD);
        Mockito.when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(true);

        UserAlreadyExistsException exception = assertThrows(UserAlreadyExistsException.class,
                () -> authenticationService.register(dto));

        assertEquals("User with that email already exists.", exception.getMessage());
        Mockito.verify(userRepository, Mockito.times(1)).existsByEmail(TEST_EMAIL);
        Mockito.verify(encoder, Mockito.never()).encode(Mockito.any(String.class));
        Mockito.verify(userRepository, Mockito.never()).save(Mockito.any(User.class));
    }

    @Test
    void shouldAuthenticateUser() {
        // Given
        LoginUserDto dto = createLoginUserDto(TEST_EMAIL, TEST_PASSWORD);
        User user = createUser(TEST_EMAIL, TEST_PASSWORD);

        String fakeToken = "fake-jwt-token";

        Mockito.when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        Mockito.when(jwtService.generateToken(TEST_EMAIL)).thenReturn(fakeToken);
        // have to hardcoded Authentication returned by authenticationManager

        //when
        String result = authenticationService.authenticate(dto);

        // assert
        assertNotNull(result);
        assertEquals(fakeToken, result);

        Mockito.verify(authenticationManager).authenticate(Mockito.any(UsernamePasswordAuthenticationToken.class));
        Mockito.verify(userRepository).findByEmail(TEST_EMAIL);
        Mockito.verify(jwtService).generateToken(TEST_EMAIL);

    }
    private RegisterUserDto crateRegisterUserDto(String email, String password) {
        RegisterUserDto dto = new RegisterUserDto();
        dto.setEmail(email);
        dto.setPassword(password);

        return dto;
    }

    private LoginUserDto createLoginUserDto(String email, String password) {
        LoginUserDto dto = new LoginUserDto();
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
