package com.example.model.dto.response;

import com.example.model.Company;
import lombok.Data;

import java.util.List;
import java.util.stream.Collectors;

@Data
public class CompanyDto {
    private Long id;
    private String name;
    private String avatarUrl;
    private List<CompanyEmployeeDto> employees;

    public CompanyDto() {}

    public CompanyDto(Company company) {
        this.id = company.getId();
        this.name = company.getName();
        this.avatarUrl = company.getAvatarUrl();
        this.employees = company.getEmployees()
                .stream()
                .map(CompanyEmployeeDto::new)
                .collect(Collectors.toList());
    }
}
