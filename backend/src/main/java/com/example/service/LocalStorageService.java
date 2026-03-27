package com.example.service;

import org.springframework.web.multipart.MultipartFile;

public interface LocalStorageService {
    String uploadFile(MultipartFile file, String fileName);
    String createCompanyDirectory(Long id);
    String createPropertyDirectory(Long propertyId, Long companyId);
}
