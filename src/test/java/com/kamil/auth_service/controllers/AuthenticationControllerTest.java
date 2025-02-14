package com.kamil.auth_service.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kamil.auth_service.exception.UserAlreadyExistsException;
import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginResponse;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.services.AuthenticationService;
import com.kamil.auth_service.services.JwtService;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.stream.Stream;

import static com.kamil.auth_service.util.TestDataFactory.*;
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

    @Autowired
    private ObjectMapper objectMapper;



    // Constants for URLs
    private static final String REGISTER_URL = "/auth/register";
    private static final String LOGIN_URL = "/auth/login";

    // Constants for test data
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "password123";
    private static final String VALID_EMAIL = "valid@email.com";
    private static final String VALID_PASSWORD = "validpassword123";
    private static final String INVALID_EMAIL = "invalid-email";
    private static final String SHORT_PASSWORD = "short";
    private static final String EMPTY_STRING = "";
    private static final String NULL_STRING = null;

    // Constants for error messages
    private static final String EMAIL_NOT_VALID = "Email is not valid";
    private static final String PASSWORD_TOO_SHORT = "Password have to be at least 8 characters long";
    private static final String EMAIL_CANNOT_BE_EMPTY = "Email cannot be empty";
    private static final String PASSWORD_CANNOT_BE_EMPTY = "Password cannot be empty";
    private static final String USER_ALREADY_EXISTS = "User already exists";
    private static final String EMAIL_ALREADY_TAKEN = "Provided email is already taken";
    private static final String INVALID_EMAIL_FORMAT = "Invalid email format";
    private static final String MALFORMED_JSON_ERROR = "Malformed JSON";
    private static final String MALFORMED_JSON_MESSAGE = "Invalid JSON format";
    private static final String AUTHENTICATION_FAILED = "Authentication failed";
    private static final String INVALID_EMAIL_MESSAGE = "Invalid email";
    private static final String INVALID_PASSWORD_MESSAGE = "Invalid password";


    @Test
    void shouldReturnRegisteredUserWhenValidRegisteredUserDto() throws Exception {
        RegisterUserDto registerUserDto = createRegisterUserDto(TEST_EMAIL, TEST_PASSWORD);
        User user = createUser(TEST_EMAIL, TEST_PASSWORD);

        when(authenticationService.register(any(RegisterUserDto.class)))
                .thenReturn(user);

        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(TEST_EMAIL))
                .andExpect(jsonPath("$.password").value(TEST_PASSWORD));

        verify(authenticationService).register(any(RegisterUserDto.class));
    }

    @ParameterizedTest
    @CsvSource({
            INVALID_EMAIL + ", " + VALID_PASSWORD + ", email, " + EMAIL_NOT_VALID,
            VALID_EMAIL + ", " + SHORT_PASSWORD + ", password, " + PASSWORD_TOO_SHORT,
            INVALID_EMAIL + ", " + SHORT_PASSWORD + ", email; password, " + EMAIL_NOT_VALID + "; " + PASSWORD_TOO_SHORT,
            EMPTY_STRING + ", " + VALID_PASSWORD + ", email, " + EMAIL_CANNOT_BE_EMPTY,
            VALID_EMAIL + ", " + EMPTY_STRING + ", password, " + PASSWORD_CANNOT_BE_EMPTY,
            EMPTY_STRING + ", " + EMPTY_STRING + ", email; password, " + EMAIL_CANNOT_BE_EMPTY + "; " + PASSWORD_CANNOT_BE_EMPTY
    })
    void shouldFailToRegisterUserWithInvalidData(String email, String password, String errorFields, String expectedErrors) throws Exception {
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto(email, password);

        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(result -> {
                    String[] fields = errorFields.split("; ");
                    String[] errors = expectedErrors.split("; ");
                    for (int i = 0; i < fields.length; i++) {
                        String field = fields[i];
                        String error = errors[i];
                        jsonPath("$." + field).value(error).match(result);
                    }
                });
    }

    @Test
    void shouldReturnBadRequestForDuplicateEmail() throws Exception {
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto(TEST_EMAIL, TEST_PASSWORD);

        when(authenticationService.register(invalidRegisterUserDto))
                .thenThrow(UserAlreadyExistsException.class);

        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value(USER_ALREADY_EXISTS))
                .andExpect(jsonPath("$.message").value(EMAIL_ALREADY_TAKEN));
    }


    static Stream<Arguments> provideMalformedRequests() {
        return Stream.of(
                Arguments.of("{ \"email\": \"test@example.com\", \"password\": \"password123\" ", "/auth/register"),
                Arguments.of("{ \"email\": \"test@example.com\", \"password\": password123 }", "/auth/register"),
                Arguments.of("{ \"email\": \"test@example.com\", \"password\": \"password123\" ", "/auth/login"),
                Arguments.of("{ \"email\": \"test@example.com\", \"password\": password123 }", "/auth/login")
        );
    }

    @ParameterizedTest
    @MethodSource("provideMalformedRequests")
    void shouldReturnBadRequestForMalformedJson(String malformedJson, String endpoint) throws Exception {
        mockMvc.perform(post(endpoint)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(malformedJson))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(MALFORMED_JSON_ERROR))
                .andExpect(jsonPath("$.message").value(MALFORMED_JSON_MESSAGE));
    }

    @Test
    void shouldReturnValidTokenAndExpirationTimeWhenValidCredentialsAreProvided() throws Exception {
        LoginUserDto loginUserDto = createLoginUserDto(TEST_EMAIL, TEST_PASSWORD);
        String validToken = "valid_token";
        Long expiration = 360000L;

        when(authenticationService.authenticate(loginUserDto)).thenReturn(validToken);
        when(jwtService.getExpirationTime()).thenReturn(expiration);

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.expiration").value(expiration));
    }

    @Test
    void shouldReturnUnauthorizedWhenUserIsNotInDatabase() throws Exception {
        LoginUserDto invalidLoginUserDto = createLoginUserDto(TEST_EMAIL, TEST_PASSWORD);

        when(authenticationService.authenticate(any(LoginUserDto.class)))
                .thenThrow(UsernameNotFoundException.class);

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value(AUTHENTICATION_FAILED))
                .andExpect(jsonPath("$.message").value(INVALID_EMAIL_MESSAGE));
    }

    @Test
    void shouldReturnUnauthorizedWhenPasswordIncorrect() throws Exception {
        LoginUserDto invalidLoginUserDto = createLoginUserDto(TEST_EMAIL, "wrongPassword");

        when(authenticationService.authenticate(any(LoginUserDto.class)))
                .thenThrow(BadCredentialsException.class);

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value(AUTHENTICATION_FAILED))
                .andExpect(jsonPath("$.message").value(INVALID_PASSWORD_MESSAGE));
    }

    @ParameterizedTest
    @CsvSource({
            INVALID_EMAIL + ", " + VALID_PASSWORD + ", email, " + EMAIL_NOT_VALID,
            EMPTY_STRING + ", " + VALID_PASSWORD + ", email, " + EMAIL_CANNOT_BE_EMPTY,
            VALID_EMAIL + ", " + EMPTY_STRING + ", password, " + PASSWORD_CANNOT_BE_EMPTY,
            EMPTY_STRING + ", " + EMPTY_STRING + ", email; password, " + EMAIL_CANNOT_BE_EMPTY + "; " + PASSWORD_CANNOT_BE_EMPTY,
            INVALID_EMAIL + ", " + EMPTY_STRING + ", email; password, " + EMAIL_NOT_VALID + "; " + PASSWORD_CANNOT_BE_EMPTY,
            "null, " + VALID_PASSWORD + ", email, " + EMAIL_CANNOT_BE_EMPTY,
            VALID_EMAIL + ", null, password, " + PASSWORD_CANNOT_BE_EMPTY,
            "null, null, email; password, " + EMAIL_CANNOT_BE_EMPTY + "; " + PASSWORD_CANNOT_BE_EMPTY
    })
    void shouldFailToLoginUserWithInvalidData(String email, String password, String errorFields, String expectedErrors) throws Exception {
        LoginUserDto invalidLoginUserDto = createLoginUserDto("null".equals(email) ? null : email, "null".equals(password) ? null : password);

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(result -> {
                    String[] fields = errorFields.split("; ");
                    String[] errors = expectedErrors.split("; ");
                    for (int i = 0; i < fields.length; i++) {
                        String field = fields[i];
                        String error = errors[i];
                        jsonPath("$." + field).value(error).match(result);
                    }
                });
    }
}