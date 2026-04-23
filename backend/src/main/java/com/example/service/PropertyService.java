package com.example.service;

import com.example.model.Company;
import com.example.model.Property;
import com.example.model.dto.request.create.PropertyCreateRequest;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface PropertyService {
    Property save(Property property);
    Property create(Property property);
    Property update(Long id, PropertyCreateRequest property);
    Property getById(Long id);
    List<Property> importFromCsv(String fileName, Company company);
    Property addImage(Long id, MultipartFile file);
}
