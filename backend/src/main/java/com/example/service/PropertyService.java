package com.example.service;

import com.example.model.Property;
import com.example.model.dto.request.CreatePropertyRequest;

public interface PropertyService {
    Property save(Property property);
    Property create(Property property);
    Property update(Long id, CreatePropertyRequest property);
    Property getById(Long id);
}
