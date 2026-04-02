package com.example.model.dto.response;

import com.example.model.Company;
import lombok.Data;

import java.util.List;
import java.util.stream.Collectors;

@Data
public class CompanyDetailDto {
    private Long id;
    private String name;
    private String avatarUrl;
    private List<EmployeeForCompanyDto> employees;
    //private List<PropertyResponse> properties;

    public CompanyDetailDto() {}

    public CompanyDetailDto(Company company) {
        this.id = company.getId();
        this.name = company.getName();
        this.avatarUrl = company.getAvatarUrl();
        this.employees = company.getEmployees()
                .stream()
                .map(ce -> new EmployeeForCompanyDto(ce.getUser(), ce.getRole()))
                .collect(Collectors.toList());

//        this.properties = company.getProperties()
//                .stream()
//                .map(PropertyResponse::new)
//                .collect(Collectors.toList());
    }
}
