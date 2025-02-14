package com.kamil.auth_service.util;

import com.kamil.auth_service.model.User;
import com.kamil.auth_service.payloads.LoginResponse;
import com.kamil.auth_service.payloads.LoginUserDto;
import com.kamil.auth_service.payloads.RegisterUserDto;

public class TestDataFactory {
    public static RegisterUserDto createRegisterUserDto(String email, String password) {
        RegisterUserDto dto = new RegisterUserDto();
        dto.setEmail(email);
        dto.setPassword(password);

        return dto;
    }

    public static LoginUserDto createLoginUserDto(String email, String password) {
        LoginUserDto dto = new LoginUserDto();
        dto.setEmail(email);
        dto.setPassword(password);

        return dto;
    }

    public static User createUser(String email, String password) {
        User user = new User();
        user.setEmail(email);
        user.setPassword(password);

        return user;
    }

    public static LoginResponse createLoginResponse(String token, Long expiration) {
        return new LoginResponse(token, expiration);
    }
}
