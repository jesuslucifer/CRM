package com.example.controller;

import com.example.model.*;
import com.example.model.dto.request.*;
import com.example.model.dto.response.*;
import com.example.model.enums.EmployeeRole;
import com.example.security.SecurityUtil;
import com.example.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@Slf4j
@RestController
@RequestMapping("/api/company")
@RequiredArgsConstructor
public class CompanyController {
    private final CompanyService companyService;
    private final UserService userService;

    @PostMapping("/create")
    public ResponseEntity<?> create(@RequestBody CompanyCreateRequest request) {
        User user = SecurityUtil.getCurrentUser();

        Company company = Company.builder()
                .name(request.getName())
                .userCreator(user)
                .avatarUrl("http://localhost:8080/uploads/avatars/default.jpg")
                .build();

        company.addEmployee(userService.getById(user.getId()), EmployeeRole.ADMIN);

        companyService.create(company);

        return ResponseEntity.ok(new CompanyDetailDto(company));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        Company company = companyService.getById(id);

        return ResponseEntity.ok(new CompanyDetailDto(company));
    }

//    @PutMapping("/{id}")
//    public ResponseEntity<?> update(
//            @PathVariable Long id,
//            @RequestBody CompanyCreateRequest request) {
//        return ResponseEntity.ok(new Compa)
//    }

    @PutMapping("/{id}/avatar")
    public SuccessResponse updateAvatarUrl(
            @RequestParam("file") MultipartFile file,
            @PathVariable Long id) {
        companyService.updateAvatarUrl(id,file);

        return new SuccessResponse(
                "Аватар обновлен",
                HttpStatus.OK
        );
    }

//    @PutMapping("/{companyId}/employees")
//    public ResponseEntity<?> addEmployee(@PathVariable Long companyId,
//                                         @RequestBody CompanyEmployeeRequest companyEmployeeRequest) {
//        companyService.addEmployee(companyEmployeeRequest.getEmployeeId(),
//                companyId,
//                companyEmployeeRequest.getEmployeeRole());
//
//        return ResponseEntity.ok(new CompanyDto(companyService.getById(companyId)));
//    }

    @PutMapping("/{companyId}/employees")
    public ResponseEntity<?> addEmployee(@PathVariable Long companyId,
                                         @RequestBody CompanyEmployeeRequest companyEmployeeRequest) {
        companyService.addEmployee(companyEmployeeRequest.getEmail(),
                companyId,
                companyEmployeeRequest.getEmployeeRole());

        return ResponseEntity.ok(new CompanyDetailDto(companyService.getById(companyId)));
    }

    @DeleteMapping("/{companyId}/{employeeId}/employees")
    public ResponseEntity<?> removeEmployee(@PathVariable Long companyId,
                                            @PathVariable Long employeeId) {
        companyService.removeEmployee(employeeId, companyId);

        return ResponseEntity.ok(new CompanyDetailDto(companyService.getById(companyId)));
    }

}
