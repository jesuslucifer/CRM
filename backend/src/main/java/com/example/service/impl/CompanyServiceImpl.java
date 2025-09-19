package com.example.service.impl;

import com.example.exception.CompanyNameAlreadyExistsException;
import com.example.exception.CompanyNotFoundException;
import com.example.exception.InvalidFileTypeException;
import com.example.exception.UploadFileIsEmptyException;
import com.example.model.Company;
import com.example.repository.CompanyRepository;
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
}
