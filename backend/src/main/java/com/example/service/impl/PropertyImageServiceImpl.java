package com.example.service.impl;

import com.example.exception.PropertyAlreadyExistsException;
import com.example.model.PropertyImage;
import com.example.repository.PropertyImageRepository;
import com.example.service.PropertyImageService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@Transactional
@RequiredArgsConstructor
public class PropertyImageServiceImpl implements PropertyImageService {
    private final PropertyImageRepository propertyImageRepository;

    @Override
    public PropertyImage findByStoredFilename(String filename) {
        return propertyImageRepository.findByStoredFilename(filename)
                .orElseThrow(PropertyAlreadyExistsException::new); // TODO: EXCEPTION
    }
}
