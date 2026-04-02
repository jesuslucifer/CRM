package com.example.service.impl;

import com.example.exception.*;
import com.example.model.*;
import com.example.model.dto.response.ClientDto;
import com.example.model.dto.response.OrderDto;
import com.example.model.enums.EmployeeRole;
import com.example.model.dto.response.PropertyResponse;
import com.example.repository.CompanyEmployeeRepository;
import com.example.repository.CompanyRepository;
import com.example.repository.UserRepository;
import com.example.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CompanyServiceImpl implements CompanyService {
    private final CompanyRepository companyRepository;
    private final LocalStorageService localStorageService;
    private final UserRepository userRepository;
    private final CompanyEmployeeRepository companyEmployeeRepository;
    private final PropertyService propertyService;
    private final OrderService orderService;
    private final DealService dealService;
    private final ClientService clientService;

    @Override
    public Company save(Company company) {
        return companyRepository.save(company);
    }

    @Override
    public Company create(Company company) {
        if (companyRepository.existsByNameAndUserCreatorId(
                company.getName(), company.getUserCreator().getId())) {
            throw new CompanyNameAlreadyExistsException();
        }

        Company createdCompany = companyRepository.save(company);

        localStorageService.createCompanyDirectory(createdCompany.getId());

        return createdCompany;
    }

    @Override
    public Company getById(Long id) {
        return companyRepository.findById(id)
                .orElseThrow(CompanyNotFoundException::new);
    }

    @Override
    public void updateAvatarUrl(Long id, MultipartFile file) {
        Company company = companyRepository.findById(id)
                .orElseThrow(CompanyNotFoundException::new);

        if (file.isEmpty()) {
            throw new UploadFileIsEmptyException();
        }

        if (!file.getContentType().startsWith("image")) {
            throw new InvalidFileTypeException();
        }

        String filename = "avatar_company_" + company.getId() + "_" + System.currentTimeMillis();
        String fileUrl = localStorageService.uploadFile(file, filename);

        company.setAvatarUrl(fileUrl);
        save(company);
    }

    @Override
    public Company addEmployee(Long userId, Long companyId, EmployeeRole role) {
        Company company = companyRepository.findById(companyId)
                .orElseThrow(CompanyNotFoundException::new);

        User user = userRepository.findById(userId)
                .orElseThrow(UserNotFoundException::new);

        if (companyEmployeeRepository.existsByCompanyIdAndUserId(companyId, userId)) {
            throw new EmployeeAlreadyExistsException();
        }

        company.addEmployee(user, role);

        return save(company);
    }

    @Override
    public Company addEmployee(String email, Long companyId, EmployeeRole role) {
        Company company = companyRepository.findById(companyId)
                .orElseThrow(CompanyNotFoundException::new);

        User user = userRepository.findByEmail(email)
                .orElseThrow(UserNotFoundException::new);

        if (companyEmployeeRepository.existsByCompanyIdAndUserEmail(companyId, email)) {
            throw new EmployeeAlreadyExistsException();
        }

        company.addEmployee(user, role);

        return save(company);
    }

    @Override
    public Company removeEmployee(Long userId, Long companyId) {
        Company company = companyRepository.findById(companyId)
                .orElseThrow(CompanyNotFoundException::new);

        User user = userRepository.findById(userId)
                .orElseThrow(UserNotFoundException::new);

        if (!companyEmployeeRepository.existsByCompanyIdAndUserId(companyId, userId)) {
            throw new EmployeeNotFoundException();
        }

        company.removeEmployee(user);

        return save(company);
    }

    @Override
    public List<PropertyResponse> getProperties(Long companyId) {
        Company company = companyRepository.findById(companyId)
                .orElseThrow(CompanyNotFoundException::new);

        return company.getProperties()
                .stream()
                .map(PropertyResponse::new)
                .collect(Collectors.toList());
    }

    @Override
    public List<OrderDto> getOrders(Long companyId) {
        Company company = companyRepository.findById(companyId)
                .orElseThrow(CompanyNotFoundException::new);

        return company.getOrders()
                .stream()
                .map(OrderDto::new)
                .collect(Collectors.toList());
    }

    @Override
    public List<ClientDto> getClients(Long companyId) {
        Company company = companyRepository.findById(companyId)
                .orElseThrow(CompanyNotFoundException::new);

        return company.getClients()
                .stream()
                .map(ClientDto::new)
                .collect(Collectors.toList());
    }

    @Override
    public Company removeProperty(Long propertyId) {
        Property property = propertyService.getById(propertyId);

        Company company = getById(property.getCompany().getId());

        company.removeProperty(property);

        return save(company);
    }

    @Override
    public Company removeOrder(Long orderId) {
        Order order = orderService.getById(orderId);

        Company company = getById(order.getCompany().getId());

        company.removeOrder(order);

        return save(company);
    }

    @Override
    public Company removeDeal(Long dealId) {
        Deal deal = dealService.getById(dealId);

        Company company = getById(deal.getCompany().getId());

        company.removeDeal(deal);

        return save(company);
    }

    @Override
    public Company removeClient(Long clientId) {
        Client client = clientService.getById(clientId);

        Company company = getById(client.getCompany().getId());

        company.removeClient(client);

        return save(company);
    }
}
