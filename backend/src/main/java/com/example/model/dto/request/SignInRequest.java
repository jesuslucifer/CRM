package com.example.model.dto.request;

import lombok.Data;

@Data
public class SignInRequest {
    private String usernameOrEmail;
    private String password;
}
