package com.example.service;

import com.example.model.Company;
import com.example.model.dto.response.ClientDto;
import com.example.model.dto.response.OrderDto;
import com.example.model.enums.EmployeeRole;
import com.example.model.dto.response.PropertyResponse;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface CompanyService {
    Company save(Company company);
    Company create(Company company);
    Company getById(Long id);
    void updateAvatarUrl(Long id, MultipartFile file);
    Company addEmployee(Long userId, Long companyId, EmployeeRole role);
    Company addEmployee(String email, Long companyId, EmployeeRole role);
    Company removeEmployee(Long userId, Long companyId);
    List<PropertyResponse> getProperties(Long companyId);
    List<OrderDto> getOrders(Long companyId);
    List<ClientDto> getClients(Long companyId);
    Company removeProperty(Long propertyId);
    Company removeOrder(Long orderId);
    Company removeDeal(Long dealId);
    Company removeClient(Long clientId);
}
