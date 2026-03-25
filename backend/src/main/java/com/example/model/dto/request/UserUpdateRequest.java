package com.example.model.dto.request;

import lombok.Data;

@Data
public class UserUpdateRequest {
    private Long id;
    private String username;
    private String name;
    private String lastName;
}
