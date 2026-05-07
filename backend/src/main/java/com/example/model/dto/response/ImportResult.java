package com.example.model.dto.response;

import com.example.model.Property;
import lombok.Data;

import java.util.List;

@Data
public class ImportResult {
    private final boolean success;
    private final String message;
    private final List<PropertyResponse> importedProperties;
    private final int count;

    private ImportResult(boolean success, String message, List<PropertyResponse> importedProperties) {
        this.success = success;
        this.message = message;
        this.importedProperties = importedProperties;
        this.count = importedProperties != null ? importedProperties.size() : 0;
    }

    public static ImportResult success(List<PropertyResponse> importedProperties, String message) {
        return new ImportResult(true, message, importedProperties);
    }

    public static ImportResult error(String message) {
        return new ImportResult(false, message, null);
    }
}
