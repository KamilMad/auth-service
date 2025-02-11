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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

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
        Mockito.when(userRepository.save(any(User.class))).thenReturn(mockUser);

        // Act
        User result = authenticationService.register(dto);

        // Assert
        assertNotNull(result);
        assertEquals(dto.getEmail(), result.getEmail());
        assertEquals(ENCODED_PASSWORD, result.getPassword());

        verify(encoder).encode("password123");
        verify(userRepository).save(any(User.class));
    }

    @Test
    void shouldThrowExceptionWhenUserAlreadyExist() {
        RegisterUserDto dto = crateRegisterUserDto(TEST_EMAIL, TEST_PASSWORD);
        Mockito.when(userRepository.existsByEmail(TEST_EMAIL)).thenReturn(true);

        UserAlreadyExistsException exception = assertThrows(UserAlreadyExistsException.class,
                () -> authenticationService.register(dto));

        assertEquals("User with that email already exists.", exception.getMessage());
        verify(userRepository, Mockito.times(1)).existsByEmail(TEST_EMAIL);
        verifyNoInteractions(encoder);
        verify(userRepository, Mockito.never()).save(any(User.class));
    }

    @Test
    void shouldReturnJwtTokenWhenCredentialAreValid() {
        // Given
        LoginUserDto dto = createLoginUserDto(TEST_EMAIL, TEST_PASSWORD);
        User user = createUser(TEST_EMAIL, TEST_PASSWORD);

        String fakeToken = "fake-jwt-token";

        Mockito.when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        Mockito.when(jwtService.generateToken(TEST_EMAIL)).thenReturn(fakeToken);

        //when
        String result = authenticationService.authenticate(dto);

        // assert
        assertNotNull(result);
        assertEquals(fakeToken, result);

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(userRepository).findByEmail(TEST_EMAIL);
        verify(jwtService).generateToken(TEST_EMAIL);

    }

    @Test
    void shouldThrowExceptionWhenCredentialsAreInvalid() {
        LoginUserDto dto = createLoginUserDto(TEST_EMAIL, TEST_PASSWORD);

        Mockito.when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid email or password."));

        assertThrows(BadCredentialsException.class, () -> authenticationService.authenticate(dto));
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verifyNoInteractions(userRepository, jwtService);
    }

    @Test
    void shouldThrowUsernameNotFoundException() {
        // Given
        LoginUserDto dto = createLoginUserDto(TEST_EMAIL, TEST_PASSWORD);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken(TEST_EMAIL, TEST_PASSWORD));

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // When
        assertThrows(UsernameNotFoundException.class, () -> authenticationService.authenticate(dto));


        // Then
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        Mockito.verify(userRepository).findByEmail(TEST_EMAIL);
        verifyNoInteractions(jwtService);
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
