package com.example.controller;

import com.example.model.dto.request.PropertyCreateRequest;
import com.example.model.dto.response.PropertyResponse;
import com.example.service.PropertyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/property")
@RequiredArgsConstructor
public class PropertyController {
    private final PropertyService propertyService;

    @GetMapping("/{id}")
    public ResponseEntity<?> createProperty(@PathVariable Long id) {
        return okDto(id);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateProperty(@PathVariable Long id, @RequestBody PropertyCreateRequest request) {
        propertyService.update(id, request);

        return okDto(id);
    }

    private ResponseEntity<?> okDto(Long id) {
        return ResponseEntity.ok(new PropertyResponse(propertyService.getById(id)));
    }
}
