package com.example.service;

import com.example.model.PropertyImage;

public interface PropertyImageService {
    PropertyImage findByStoredFilename(String filename);
}
