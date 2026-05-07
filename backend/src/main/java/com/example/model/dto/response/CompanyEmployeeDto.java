package com.example.model.dto.response;

import com.example.model.CompanyEmployee;
import com.example.model.enums.EmployeeRole;
import lombok.Data;

@Data
public class CompanyEmployeeDto {
    UserDto user;
    EmployeeRole role;

    public CompanyEmployeeDto(CompanyEmployee companyEmployee) {
        this.user = new UserDto(companyEmployee.getUser());
        this.role = companyEmployee.getRole();
    }
}
