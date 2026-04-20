package com.example.controller;

import com.example.model.Company;
import com.example.model.Property;
import com.example.model.dto.request.PropertyCreateRequest;
import com.example.model.dto.response.ImportResult;
import com.example.model.dto.response.PropertyResponse;
import com.example.service.CompanyService;
import com.example.service.PropertyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/company/{companyId}/properties")
@RequiredArgsConstructor
public class CompanyPropertyController {
    private final CompanyService companyService;
    private final PropertyService propertyService;

    @GetMapping
    public ResponseEntity<?> getAll(@PathVariable Long companyId) {
        return ResponseEntity.ok(
                companyService.getProperties(companyId));
    }

    @PostMapping
    public ResponseEntity<?> create(
            @PathVariable Long companyId,
            @RequestBody PropertyCreateRequest request) {
        Company company = companyService.getById(companyId);

        Property property = Property.builder()
                .cadastralNumber(request.getCadastralNumber())
                .company(company)
                .title(request.getTitle())
                .description(request.getDescription())
                .propertyType(request.getPropertyType())
                .dealType(request.getDealType())
                .address(request.getAddress())
                .city(request.getCity())
                .district(request.getDistrict())
                .price(request.getPrice())
                .salePrice(request.getSalePrice())
                .area(request.getArea())
                .rooms(request.getRooms())
                .floor(request.getFloor())
                .totalFloors(request.getTotalFloors())
                .yearBuilt(request.getYearBuilt())
                .status(request.getPropertyStatus())
                .build();

        propertyService.create(property);

        company.addProperty(property);

        return ResponseEntity.ok(new PropertyResponse(property, company));
    }

    @PostMapping("/import-from-csv")
    public ResponseEntity<?> importFromCsvNio(
            @RequestParam("file") MultipartFile file,
            @PathVariable Long companyId) {

        log.info("Получен запрос на импорт CSV файла (NIO): {}, companyId: {}",
                file.getOriginalFilename(), companyId);

        Path tempFile = null;

        try {
            Company company = companyService.getById(companyId);

            tempFile = Files.createTempFile("import_", "_" + file.getOriginalFilename());

            file.transferTo(tempFile.toFile());

            log.debug("Временный файл создан (NIO): {}", tempFile.toAbsolutePath());

            List<Property> importedProperties = propertyService.importFromCsv(
                    tempFile.toAbsolutePath().toString(),
                    company
            );

            return ResponseEntity.ok("Импорт успешно завершен");

        } catch (IOException e) {
            log.error("Ошибка при обработке файла (NIO): {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ImportResult.error("Ошибка при обработке файла: " + e.getMessage()));
        } catch (Exception e) {
            log.error("Неожиданная ошибка при импорте (NIO): {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ImportResult.error("Внутренняя ошибка сервера: " + e.getMessage()));
        } finally {
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                    log.debug("Временный файл удален (NIO): {}", tempFile.toAbsolutePath());
                } catch (IOException e) {
                    log.warn("Не удалось удалить временный файл (NIO): {}", tempFile.toAbsolutePath(), e);
                }
            }
        }
    }
}
