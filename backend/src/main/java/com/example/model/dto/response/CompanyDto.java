package com.example.model.dto.response;

import com.example.model.Company;
import lombok.Data;

@Data
public class CompanyDto {
    private Long id;
    private String name;
    private String avatarUrl;

    public CompanyDto() {}

    public CompanyDto(Company company) {
        this.id = company.getId();
        this.name = company.getName();
        this.avatarUrl = company.getAvatarUrl();
    }
}
