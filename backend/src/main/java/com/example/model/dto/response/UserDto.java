package com.example.model.dto.response;

import com.example.model.User;
import lombok.Data;

import java.util.List;
import java.util.stream.Collectors;

@Data
public class UserDto {
    private Long id;
    private String username;
    private String email;
    private String avatarUrl;
    private String name;
    private String lastName;
    private List<CompanyForUserDto> companies;

    public UserDto() {}

    public UserDto(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.avatarUrl = user.getAvatarUrl();
        this.name = user.getName();
        this.lastName = user.getLastName();
        this.companies = user.getCompanyEmployees()
                .stream()
                .map(ce -> new CompanyForUserDto(ce.getCompany(), ce.getRole()))
                .collect(Collectors.toList());
    }
}
