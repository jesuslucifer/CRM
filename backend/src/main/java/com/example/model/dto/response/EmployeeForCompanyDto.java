package com.example.model.dto.response;

import com.example.model.enums.EmployeeRole;
import com.example.model.User;
import lombok.Data;

@Data
public class EmployeeForCompanyDto {
    private Long id;
    private String username;
    private String email;
    private String avatarUrl;
    private String name;
    private String lastName;
    private EmployeeRole role;

    public EmployeeForCompanyDto() {}

    public EmployeeForCompanyDto(User user, EmployeeRole role) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.avatarUrl = user.getAvatarUrl();
        this.name = user.getName();
        this.lastName = user.getLastName();
        this.role = role;
    }
}
