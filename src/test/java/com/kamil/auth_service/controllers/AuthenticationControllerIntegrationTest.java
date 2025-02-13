package com.kamil.auth_service.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginResponse;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.repository.UserRepository;
import com.kamil.auth_service.services.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.AssertionsForClassTypes.not;
import static org.hamcrest.Matchers.isEmptyOrNullString;
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

    @Test
    void shouldFailToRegisterUserWithInvalidEmail() throws Exception{
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto("invalid-email", "validpassword123");

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email").value("Email is not valid"));
    }

    @Test
    void shouldFailToRegisterUserWithInvalidPassword() throws Exception{
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto("valid@email.com", "short");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value("Password have to be at least 8 characters long"));
    }

    @Test
    void shouldFailToRegisterUserWithInvalidEmailAndPassword() throws Exception{
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto("invalid-email", "short");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value("Password have to be at least 8 characters long"))
                .andExpect(jsonPath("$.email").value("Email is not valid"));
    }

    @Test
    void shouldFailToRegisterUserWithNullEmail() throws Exception{
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto(null, "validpassword123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email").value("Email cannot be empty"));
    }

    @Test
    void shouldFailToRegisterUserWithNullPassword() throws Exception{
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto("valid@email.com", null);

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value("Password cannot be empty"));
    }

    @Test
    void shouldFailToRegisterUserWithNullEmailAndPassword() throws Exception{
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto(null, null);

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email").value("Email cannot be empty"))
                .andExpect(jsonPath("$.password").value("Password cannot be empty"));
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
                .content(new ObjectMapper().writeValueAsString(loginUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists()) // Token field exists
                .andExpect(jsonPath("$.token").isString()) // Token is a string
                .andExpect(jsonPath("$.token").value(matchesPattern("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+$"))) // Validate JWT format
                .andExpect(jsonPath("$.expiration").exists()); // Expiration field exists

    }

    @Test
    void shouldReturnUBadRequestWhenInvalidEmail() throws Exception {
        LoginUserDto invalidLoginUserDto = createLoginUserDto("invalid-email", "validpassword123");
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidLoginUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email").value("Invalid email format"));

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
