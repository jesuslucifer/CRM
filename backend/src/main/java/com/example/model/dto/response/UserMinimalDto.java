package com.example.model.dto.response;

import com.example.model.User;
import lombok.Data;

@Data
public class UserMinimalDto {
    private Long id;
    private String username;
    private String avatarUrl;
    private String name;
    private String lastName;

    public UserMinimalDto(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.avatarUrl = user.getAvatarUrl();
        this.name = user.getName();
        this.lastName = user.getLastName();
    }
}
