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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
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
