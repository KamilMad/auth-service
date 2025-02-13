package com.kamil.auth_service.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginResponse;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.services.AuthenticationService;
import com.kamil.auth_service.services.JwtService;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthenticationController.class)
@AutoConfigureMockMvc(addFilters = false)
public class AuthenticationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthenticationService authenticationService;

    @MockitoBean
    private JwtService jwtService;

    private final String TEST_EMAIL = "test@example.com";
    private final String TEST_PASSWORD = "password123";

    private final String invalidEmail = "Email is not valid";
    private final String emptyEmail = "Email cannot be empty";

    private final String emptyPassword = "Password cannot be empty";
    private final String tooShortPassword = "Password have to be at least 8 characters long";

    @Test
    void shouldReturnRegisteredUserValidRegisteredUserDto() throws Exception {
        RegisterUserDto registerUserDto = createRegisterUserDto(TEST_EMAIL, TEST_PASSWORD);
        User user = createUser(TEST_EMAIL, TEST_PASSWORD);

        when(authenticationService.register(any(RegisterUserDto.class)))
                .thenReturn(user);

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(registerUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(TEST_EMAIL))
                .andExpect(jsonPath("$.password").value(TEST_PASSWORD));

        verify(authenticationService).register(any(RegisterUserDto.class));
    }

    @Test
    void shouldReturnBadRequestForInvalidEmail() throws Exception {
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto("invalid-email", TEST_PASSWORD);

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email")
                        .value(invalidEmail));
    }

    @Test
    void shouldReturnBadRequestForEmptyEmail() throws Exception{
        RegisterUserDto invalidRegisteredUserDto = createRegisterUserDto("", TEST_PASSWORD);

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email").value(emptyEmail));
    }



    @Test
    void shouldReturnBadRequestForTooShortPassword() throws Exception {
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto(TEST_EMAIL, "short");

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value(tooShortPassword));
    }

    @Test
    void shouldReturnBadRequestForEmptyPassword() throws Exception {
        RegisterUserDto invalidRRegisteredUserDto = createRegisterUserDto(TEST_EMAIL,"");

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidRRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value(Matchers.containsInAnyOrder(
                        tooShortPassword,
                        emptyPassword
                )));
    }

    @Test
    void shouldReturnBadRequestForInvalidEmailAndTooShortPassword() throws Exception{
        RegisterUserDto invalidRRegisteredUserDto = createRegisterUserDto("invalid-email","short");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value(tooShortPassword))
                .andExpect(jsonPath("$.email").value(invalidEmail));
    }

    @Test
    void shouldReturnBadRequestForInvalidEmailAndEmptyPassword() throws Exception{
        RegisterUserDto invalidRRegisteredUserDto = createRegisterUserDto("invalid-email","");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value(Matchers.containsInAnyOrder(
                        tooShortPassword,
                        emptyPassword
                )))
                .andExpect(jsonPath("$.email").value(invalidEmail));
    }

    @Test
    void shouldReturnBadRequestForEmptyEmailAndTooShortPassword() throws Exception{
        RegisterUserDto invalidRRegisteredUserDto = createRegisterUserDto("","short");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value(
                        tooShortPassword))
                .andExpect(jsonPath("$.email").value(emptyEmail));
    }

    @Test
    void shouldReturnBadRequestForEmptyEmailAndEmptyPassword() throws Exception{
        RegisterUserDto invalidRRegisteredUserDto = createRegisterUserDto("","");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value(Matchers.containsInAnyOrder(
                        tooShortPassword,
                        emptyPassword
                )))
                .andExpect(jsonPath("$.email").value(emptyEmail));
    }

    @Test
    void shouldReturnValidTokenAndExpirationTimeWhenValidCredentialsAreProvided() throws Exception{
        LoginUserDto loginUserDto = createLoginUserDto(TEST_EMAIL, TEST_PASSWORD);
        String validToken = "valid_token";
        Long expiration = 360000L;
        when(authenticationService.authenticate(loginUserDto)).thenReturn(validToken);

        when(jwtService.getExpirationTime()).thenReturn(expiration);

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(loginUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.expiration").value(expiration));

    }

    @Test
    void shouldReturnUnauthorizedWhenUserIsNotInADatabase() throws Exception{
        LoginUserDto invalidLoginUserDto = createLoginUserDto(TEST_EMAIL, TEST_PASSWORD);
        when(authenticationService.authenticate(any(LoginUserDto.class)))
                .thenThrow(UsernameNotFoundException.class);

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Authentication failed"))
                .andExpect(jsonPath("$.message").value("Invalid email"));

    }

    @Test
    void shouldReturnUnauthorizedWhenPasswordIncorrect() throws Exception {
        LoginUserDto invalidLoginUserDto = createLoginUserDto(TEST_EMAIL, "wrongPassword");

        when(authenticationService.authenticate(any(LoginUserDto.class)))
                .thenThrow(BadCredentialsException.class);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Authentication failed"))
                .andExpect(jsonPath("$.message").value("Invalid password"));
    }

    @Test
    void shouldReturnUnauthorizedWhenInvalidEmailFormat() throws Exception{
        LoginUserDto invalidLoginUserDto = createLoginUserDto("invalid-email", TEST_PASSWORD);

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email").value("Invalid email format"));
    }

    @Test
    void shouldReturnUnauthorizedWhenEmptyEmail() throws Exception{
        LoginUserDto invalidLoginUserDto = createLoginUserDto("", TEST_PASSWORD);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email").value("Email cannot be empty"));
    }

    @Test
    void shouldReturnUnauthorizedWhenEmptyPassword() throws Exception{
        LoginUserDto invalidLoginUserDto = createLoginUserDto(TEST_EMAIL, "");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value("Password cannot be empty"));
    }

    private RegisterUserDto createRegisterUserDto(String email, String password) {
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

    private LoginResponse createLoginResponse(String token, Long expiration) {
        return new LoginResponse(token, expiration);
    }
}
