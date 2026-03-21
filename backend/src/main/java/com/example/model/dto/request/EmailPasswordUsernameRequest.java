package com.example.model.dto.request;

import lombok.Data;

@Data
public class EmailPasswordUsernameRequest {
    private String email;
    private String password;
    private String username;
}
