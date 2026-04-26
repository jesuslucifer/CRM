package com.example.model.dto.response;

import com.example.model.Company;
import lombok.Data;

@Data
public class CompanyMinimalDto {
    private Long id;
    private String name;
    private String avatarUrl;

    public CompanyMinimalDto(Company company) {
        this.id = company.getId();
        this.name = company.getName();
        this.avatarUrl = company.getAvatarUrl();
    }
}
