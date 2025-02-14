package com.kamil.auth_service.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginResponse;
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

    @BeforeEach
    void setUp() {
        userRepository.deleteAll(); // Ensure a clean state
    }

    @Test
    void shouldRegisterUserSuccessfully() throws Exception {
        RegisterUserDto registerUserDto = createRegisterUserDto("newuser@o2.pl", "password123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("newuser@o2.pl"));
    }

    @ParameterizedTest
    @CsvSource({
            "invalid-email, validpassword123, email, Email is not valid",
            "valid@email.com, short, password, Password have to be at least 8 characters long",
            "invalid-email, short, email; password, Email is not valid; Password have to be at least 8 characters long",
            ", validpassword123, email, Email cannot be empty",
            "valid@email.com, , password, Password cannot be empty",
            ", , email; password, Email cannot be empty; Password cannot be empty"
    })
    void shouldFailToRegisterUserWithInvalidData(String email, String password, String errorFields, String expectedErrors) throws Exception {
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto(email, password);

        mockMvc.perform(post("/auth/register")
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
        User existingUser = createUser("valid@email.com", "validpassword123");
        userRepository.save(existingUser);

        LoginUserDto invalidLoginUserDto = createLoginUserDto("valid@email.com", "validpassword123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("User already exists"))
                .andExpect(jsonPath("$.message").value("Provided email is already taken"));
    }

    @Test
    void shouldSuccessfulLogin() throws Exception{
        LoginUserDto loginUserDto = createLoginUserDto("valid@email.com", "validpassword123");

        User user = new User();
        user.setEmail(loginUserDto.getEmail());
        user.setPassword(encoder.encode(loginUserDto.getPassword()));
        userRepository.save(user);

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists()) // Token field exists
                .andExpect(jsonPath("$.token").isString()) // Token is a string
                .andExpect(jsonPath("$.token").value(matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+$"))) // Validate JWT format
                .andExpect(jsonPath("$.expiration").exists()); // Expiration field exists

    }

    @Test
    void shouldSuccessfulLoginAfterRegistration() throws Exception{
        RegisterUserDto registerUserDto = createRegisterUserDto("valid@email.com", "validpassword123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerUserDto)))
                .andExpect(status().isOk());

        LoginUserDto loginUserDto = createLoginUserDto("valid@email.com", "validpassword123");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(loginUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists()) // Token field exists
                .andExpect(jsonPath("$.token").isString()) // Token is a string
                .andExpect(jsonPath("$.token").value(matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+$"))) // Validate JWT format
                .andExpect(jsonPath("$.expiration").exists()); // Expiration field exists

    }

    @Test
    void shouldReturnUnauthorizedWithWrongPassword() throws Exception{
        LoginUserDto invalidLoginUserDto = createLoginUserDto("valid@email.com", "wrongpassword");
        RegisterUserDto registerUserDto = createRegisterUserDto("valid@email.com", "password123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerUserDto)))
                .andExpect(status().isOk());

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @CsvSource({
            "'invalid-email', 'validpassword123', 'email', 'Invalid email format'",
            "'', 'validpassword123', 'email', 'Email cannot be empty'",
            "'valid@email.com', '', 'password', 'Password cannot be empty'",
            "'', '', 'email; password', 'Email cannot be empty; Password cannot be empty'",
    })
    void shouldReturnBadRequestWithInvalidCredentials(String email, String password, String errorFields, String expectedErrors) throws Exception{
        LoginUserDto invalidLoginUserDto = createLoginUserDto(email, password);

        mockMvc.perform(post("/auth/login")
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
