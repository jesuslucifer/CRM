package com.example.model.dto.response;

import com.example.model.Company;
import com.example.model.enums.EmployeeRole;
import lombok.Data;

@Data
public class CompanyForUserDto {
    private Long id;
    private String name;
    private String avatarUrl;
    private EmployeeRole role;

    public CompanyForUserDto() {}

    public CompanyForUserDto(Company company, EmployeeRole role) {
        this.id = company.getId();
        this.name = company.getName();
        this.avatarUrl = company.getAvatarUrl();
        this.role = role;
    }
}
