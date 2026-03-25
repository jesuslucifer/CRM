package com.example.service;

import com.example.model.Property;
import com.example.model.dto.request.PropertyCreateRequest;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface PropertyService {
    Property save(Property property);
    Property create(Property property);
    Property update(Long id, PropertyCreateRequest property);
    Property getById(Long id);
    List<Property> importFromCsv(String fileName, Long companyId);
    Property addPhoto(Long id, MultipartFile file);
}
