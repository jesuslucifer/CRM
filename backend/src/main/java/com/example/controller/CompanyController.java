package com.example.controller;

import com.example.model.Company;
import com.example.model.dto.request.CreateCompanyRequest;
import com.example.model.dto.response.CompanyDto;
import com.example.model.dto.response.SuccessResponse;
import com.example.security.SecurityUtil;
import com.example.service.CompanyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/company")
@RequiredArgsConstructor
public class CompanyController {
    private final CompanyService companyService;

    @PostMapping("/create")
    public ResponseEntity<?> create(@RequestBody CreateCompanyRequest request) {
        Company company = Company.builder()
                .name(request.getName())
                .userCreator(SecurityUtil.getCurrentUser())
                .avatarUrl("http://localhost:8080/uploads/avatars/default.jpg")
                .build();

        companyService.create(company);

        return ResponseEntity.ok(new CompanyDto(company));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        Company company = companyService.getById(id);

        return ResponseEntity.ok(new CompanyDto(company));
    }

    @PutMapping("/{id}/avatar")
    public SuccessResponse updateAvatarUrl(@RequestParam("file") MultipartFile file, @PathVariable Long id) {
        companyService.updateAvatarUrl(id,file);

        return new SuccessResponse(
                "Аватар обновлен",
                HttpStatus.OK
        );
    }
}
