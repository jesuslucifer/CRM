package com.example.service.impl;

import com.example.exception.*;
import com.example.model.Company;
import com.example.model.EmployeeRole;
import com.example.model.User;
import com.example.repository.CompanyEmployeeRepository;
import com.example.repository.CompanyRepository;
import com.example.repository.UserRepository;
import com.example.service.CompanyService;
import com.example.service.LocalStorageService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
@RequiredArgsConstructor
public class CompanyServiceImpl implements CompanyService {
    private final CompanyRepository companyRepository;
    private final LocalStorageService localStorageService;
    private final UserRepository userRepository;
    private final CompanyEmployeeRepository companyEmployeeRepository;

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

        return save(company);
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
            throw new EmployeeAlreadyExistsInCompanyException();
        }

        company.addEmployee(user, role);

        return companyRepository.save(company);
    }

    @Override
    public Company addEmployee(String email, Long companyId, EmployeeRole role) {
        Company company = companyRepository.findById(companyId)
                .orElseThrow(CompanyNotFoundException::new);

        User user = userRepository.findByEmail(email)
                .orElseThrow(UserNotFoundException::new);

        if (companyEmployeeRepository.existsByCompanyIdAndUserEmail(companyId, email)) {
            throw new EmployeeAlreadyExistsInCompanyException();
        }

        company.addEmployee(user, role);

        return companyRepository.save(company);
    }

    @Override
    public Company removeEmployee(Long userId, Long companyId) {
        Company company = companyRepository.findById(companyId)
                .orElseThrow(CompanyNotFoundException::new);

        User user = userRepository.findById(userId)
                .orElseThrow(UserNotFoundException::new);

        if (!companyEmployeeRepository.existsByCompanyIdAndUserId(companyId, userId)) {
            throw new EmployeeNotFoundInCompanyException();
        }

        company.removeEmployee(user);

        return companyRepository.save(company);
    }
}
