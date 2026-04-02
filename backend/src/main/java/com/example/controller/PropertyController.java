package com.example.controller;

import com.example.model.dto.request.PropertyCreateRequest;
import com.example.model.dto.response.PropertyResponse;
import com.example.model.dto.response.SuccessResponse;
import com.example.service.CompanyService;
import com.example.service.PropertyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/property/{propertyId}")
@RequiredArgsConstructor
public class PropertyController {
    private final PropertyService propertyService;
    private final CompanyService companyService;

    @GetMapping
    public ResponseEntity<?> get(@PathVariable Long propertyId) {
        return ResponseEntity.ok(new PropertyResponse(
                propertyService.getById(propertyId)));
    }

    @PutMapping
    public ResponseEntity<?> update(@PathVariable Long propertyId,
                                    @RequestBody PropertyCreateRequest request) {

        return ResponseEntity.ok(new PropertyResponse(
                propertyService.update(propertyId, request)));
    }

    @DeleteMapping
    public ResponseEntity<?> remove(
            @PathVariable Long propertyId) {
        companyService.removeProperty(propertyId);

        return ResponseEntity.ok(new SuccessResponse(
                "Недвижимость удалена",
                HttpStatus.OK));
    }
}
