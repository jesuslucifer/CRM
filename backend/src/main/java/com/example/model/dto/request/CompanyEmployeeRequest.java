package com.example.model.dto.request;

import com.example.model.EmployeeRole;
import lombok.Data;

@Data
public class CompanyEmployeeRequest {
    private Long employeeId;
    private String email;
    private EmployeeRole employeeRole;
}
