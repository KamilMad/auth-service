package com.kamil.auth_service.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kamil.auth_service.config.SecurityConfig;
import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;
import com.kamil.auth_service.services.AuthenticationService;
import com.kamil.auth_service.services.JwtService;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

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
    private final String ENCODED_PASSWORD = "$2a$10$VvZGG9s9bbUem.KQwM3R3eI.RndT1ZZgXU3yXny0nTQpeA5O0JygO";

    @Test
    void shouldReturnRegisteredUserValidRegisteredUserDto() throws Exception {
        RegisterUserDto registerUserDto = createRegisterUserDto(TEST_EMAIL, TEST_PASSWORD);
        User user = createUser(TEST_EMAIL, TEST_PASSWORD);

        Mockito.when(authenticationService.register(Mockito.any(RegisterUserDto.class)))
                .thenReturn(user);

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(registerUserDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(TEST_EMAIL))
                .andExpect(jsonPath("$.password").value(TEST_PASSWORD));

        Mockito.verify(authenticationService).register(Mockito.any(RegisterUserDto.class));
    }

    @Test
    void shouldReturnBadRequestForInvalidEmail() throws Exception {
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto("invalid-email", TEST_PASSWORD);

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email")
                        .value("Email is not valid"));
    }

    @Test
    void shouldReturnBadRequestForEmptyEmail() throws Exception{
        RegisterUserDto invalidRegisteredUserDto = createRegisterUserDto("", TEST_PASSWORD);

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.email").value("Email cannot be empty"));
    }



    @Test
    void shouldReturnBadRequestForTooShortPassword() throws Exception {
        RegisterUserDto invalidRegisterUserDto = createRegisterUserDto(TEST_EMAIL, "short");

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidRegisterUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value("Password have to be at least 8 characters long"));
    }

    @Test
    void shouldReturnBadRequestForEmptyPassword() throws Exception {
        RegisterUserDto invalidRRegisteredUserDto = createRegisterUserDto(TEST_EMAIL,"");

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(invalidRRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value(Matchers.containsInAnyOrder(
                        "Password have to be at least 8 characters long",
                        "Password cannot be empty"
                )));
    }

    @Test
    void shouldReturnBadRequestForInvalidEmailAndTooShortPassword() throws Exception{
        RegisterUserDto invalidRRegisteredUserDto = createRegisterUserDto("invalid-email","short");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value("Password have to be at least 8 characters long"))
                .andExpect(jsonPath("$.email").value("Email is not valid"));
    }

    @Test
    void shouldReturnBadRequestForInvalidEmailAndEmptyPassword() throws Exception{
        RegisterUserDto invalidRRegisteredUserDto = createRegisterUserDto("invalid-email","");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value(Matchers.containsInAnyOrder(
                        "Password have to be at least 8 characters long",
                        "Password cannot be empty"
                )))
                .andExpect(jsonPath("$.email").value("Email is not valid"));
    }

    @Test
    void shouldReturnBadRequestForEmptyEmailAndTooShortPassword() throws Exception{
        RegisterUserDto invalidRRegisteredUserDto = createRegisterUserDto("","short");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value(
                        "Password have to be at least 8 characters long"))
                .andExpect(jsonPath("$.email").value("Email cannot be empty"));
    }

    @Test
    void shouldReturnBadRequestForEmptyEmailAndEmptyPassword() throws Exception{
        RegisterUserDto invalidRRegisteredUserDto = createRegisterUserDto("","");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRRegisteredUserDto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").value(Matchers.containsInAnyOrder(
                        "Password have to be at least 8 characters long",
                        "Password cannot be empty"
                )))
                .andExpect(jsonPath("$.email").value("Email cannot be empty"));
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
}
