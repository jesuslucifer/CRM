package com.example.service;

import com.example.model.Company;
import com.example.model.EmployeeRole;
import org.springframework.web.multipart.MultipartFile;

public interface CompanyService {
    Company save(Company company);
    Company create(Company company);
    Company getById(Long id);
    void updateAvatarUrl(Long id, MultipartFile file);
    Company addEmployee(Long userId, Long companyId, EmployeeRole role);
    Company removeEmployee(Long userId, Long companyId);
}
