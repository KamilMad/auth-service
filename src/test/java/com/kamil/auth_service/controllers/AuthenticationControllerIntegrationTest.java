package com.kamil.auth_service.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.repository.UserRepository;
import com.kamil.auth_service.services.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static com.kamil.auth_service.util.TestDataFactory.*;
import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthenticationControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private BCryptPasswordEncoder encoder;

    @Autowired
    private JwtService jwtService;

    // Constants for URLs
    private static final String REGISTER_URL = "/auth/register";
    private static final String LOGIN_URL = "/auth/login";

    // Constants for test data
    private static final String VALID_EMAIL = "valid@email.com";
    private static final String VALID_PASSWORD = "validpassword123";
    private static final String INVALID_EMAIL = "invalid-email";
    private static final String SHORT_PASSWORD = "short";
    private static final String EMPTY_STRING = "";

    // Constants for error messages
    private static final String EMAIL_NOT_VALID = "Email is not valid";
    private static final String PASSWORD_TOO_SHORT = "Password have to be at least 8 characters long";
    private static final String EMAIL_CANNOT_BE_EMPTY = "Email cannot be empty";
    private static final String PASSWORD_CANNOT_BE_EMPTY = "Password cannot be empty";
    private static final String USER_ALREADY_EXISTS = "User already exists";
    private static final String EMAIL_ALREADY_TAKEN = "Provided email is already taken";

    private RegisterUserDto registerUserDto;
    private LoginUserDto loginUserDto;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll(); // Ensure a clean state

        // Initialize DTOs with default values
        registerUserDto = createRegisterUserDto(VALID_EMAIL, VALID_PASSWORD);
        loginUserDto = createLoginUserDto(VALID_EMAIL, VALID_PASSWORD);
    }

    @Test
    void shouldRegisterUserSuccessfully() throws Exception {
        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerUserDto)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(VALID_EMAIL));
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
    void shouldReturnConflictWithExistingEmail() throws Exception {
        User existingUser = createUser(VALID_EMAIL, VALID_PASSWORD);
        userRepository.save(existingUser);

        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerUserDto)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value(USER_ALREADY_EXISTS))
                .andExpect(jsonPath("$.message").value(EMAIL_ALREADY_TAKEN));
    }

    @Test
    void shouldSuccessfulLogin() throws Exception {
        User user = new User();
        user.setEmail(loginUserDto.getEmail());
        user.setPassword(encoder.encode(loginUserDto.getPassword()));
        userRepository.save(user);

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists()) // Token field exists
                .andExpect(jsonPath("$.token").isString()) // Token is a string
                .andExpect(jsonPath("$.token").value(matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+$"))) // Validate JWT format
                .andExpect(jsonPath("$.expiration").exists()); // Expiration field exists
    }

    @Test
    void shouldSuccessfulLoginAfterRegistration() throws Exception {
        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerUserDto)))
                .andExpect(status().isCreated());

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists()) // Token field exists
                .andExpect(jsonPath("$.token").isString()) // Token is a string
                .andExpect(jsonPath("$.token").value(matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+$"))) // Validate JWT format
                .andExpect(jsonPath("$.expiration").exists()); // Expiration field exists
    }

    @Test
    void shouldReturnUnauthorizedWithWrongPassword() throws Exception {
        LoginUserDto invalidLoginUserDto = createLoginUserDto(VALID_EMAIL, "wrongpassword");

        mockMvc.perform(post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerUserDto)))
                .andExpect(status().isOk());

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @CsvSource({
            INVALID_EMAIL + ", " + VALID_PASSWORD + ", email, " + EMAIL_NOT_VALID,
            EMPTY_STRING + ", " + VALID_PASSWORD + ", email, " + EMAIL_CANNOT_BE_EMPTY,
            VALID_EMAIL + ", " + EMPTY_STRING + ", password, " + PASSWORD_CANNOT_BE_EMPTY,
            EMPTY_STRING + ", " + EMPTY_STRING + ", email; password, " + EMAIL_CANNOT_BE_EMPTY + "; " + PASSWORD_CANNOT_BE_EMPTY
    })
    void shouldReturnBadRequestWithInvalidCredentials(String email, String password, String errorFields, String expectedErrors) throws Exception {
        LoginUserDto invalidLoginUserDto = createLoginUserDto(email, password);

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidLoginUserDto)))
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