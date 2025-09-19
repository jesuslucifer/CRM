package com.example.model.dto.response;

import com.example.model.User;
import lombok.Data;

@Data
public class UserDto {
    private Long id;
    private String username;
    private String email;
    private String avatarUrl;
    private String name;
    private String lastName;

    public UserDto() {}

    public UserDto(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.avatarUrl = user.getAvatarUrl();
        this.name = user.getName();
        this.lastName = user.getLastName();
    }
}
