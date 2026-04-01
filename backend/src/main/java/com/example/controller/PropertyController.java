package com.example.controller;

import com.example.model.dto.request.PropertyCreateRequest;
import com.example.model.dto.response.PropertyResponse;
import com.example.service.PropertyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/property")
@RequiredArgsConstructor
public class PropertyController {
    private final PropertyService propertyService;

    @GetMapping("/{id}")
    public ResponseEntity<?> createProperty(@PathVariable Long id) {
        return okDto(id);
    }



//    public ResponseEntity<?> addPhoto(@PathVariable Long id,
//                                      @RequestParam("file") MultipartFile file) {
//
//    }

    private ResponseEntity<?> okDto(Long id) {
        return ResponseEntity.ok(new PropertyResponse(propertyService.getById(id)));
    }
}
