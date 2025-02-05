package com.kamil.auth_service.payloads;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterUserDto {

    private String email;
    private String password;

}
