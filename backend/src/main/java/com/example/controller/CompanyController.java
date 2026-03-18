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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/company")
@RequiredArgsConstructor
public class CompanyController {
    private final CompanyService companyService;
    private final UserService userService;
    private final PropertyService propertyService;
    private final ClientService clientService;
    private final OrderService orderService;

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

    @PostMapping("/{id}/property/create")
    public ResponseEntity<?> createProperty(
            @PathVariable Long id,
            @RequestBody PropertyCreateRequest request) {
        Company company = companyService.getById(id);

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

    @PostMapping("/{id}/order/create")
    public ResponseEntity<?> createOrder(
            @PathVariable Long id,
            @RequestBody OrderCreateRequest request) {
        Company company = companyService.getById(id);
        Client client = clientService.getById(request.getClientId());

        Order order = Order.builder()
                .company(company)
                .client(client)
                .city(request.getCity())
                .dealType(request.getDealType())
                .propertyType(request.getPropertyType())
                .description(request.getDescription())
                .build();

        orderService.create(order);

        client.addOrder(order);

        return ResponseEntity.ok(new OrderDto(order));
    }

    @PostMapping("/{id}/client/create")
    public ResponseEntity<?> createClient(
            @PathVariable Long id,
            @RequestBody ClientCreateRequest request) {
        Company company = companyService.getById(id);

        Client client = Client.builder()
                .company(company)
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phone(request.getPhone())
                .email(request.getEmail())
                .clientType(request.getClientType())
                .clientSource(request.getClientSource())
                .notes(request.getNotes())
                .build();

        clientService.create(client);

        company.addClient(client);

        return ResponseEntity.ok(new ClientDto(client));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        Company company = companyService.getById(id);

        return ResponseEntity.ok(new CompanyDetailDto(company));
    }

    @GetMapping("/{id}/properties")
    public ResponseEntity<?> getProperties(@PathVariable Long id) {
        return ResponseEntity.ok(companyService.getProperties(id));
    }

    @GetMapping("/{id}/orders")
    public ResponseEntity<?> getOrders(@PathVariable Long id) {
        return ResponseEntity.ok(companyService.getOrders(id));
    }

    @GetMapping("/{id}/clients")
    public ResponseEntity<?> getClients(@PathVariable Long id) {
        return ResponseEntity.ok(companyService.getClients(id));
    }

    @PutMapping("/{id}/avatar")
    public SuccessResponse updateAvatarUrl(@RequestParam("file") MultipartFile file, @PathVariable Long id) {
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

    @PostMapping("/{id}/import-from-csv")
    public ResponseEntity<?> importFromCsvNio(
            @RequestParam("file") MultipartFile file,
            @PathVariable("id") Long companyId) {

        log.info("Получен запрос на импорт CSV файла (NIO): {}, companyId: {}",
                file.getOriginalFilename(), companyId);

        Path tempFile = null;

        try {
            // Создаем временный файл с помощью NIO
            tempFile = Files.createTempFile("import_", "_" + file.getOriginalFilename());

            // Копируем содержимое MultipartFile во временный файл
            file.transferTo(tempFile.toFile());

            log.debug("Временный файл создан (NIO): {}", tempFile.toAbsolutePath());

            // Вызываем сервис для импорта
            List<Property> importedProperties = propertyService.importFromCsv(
                    tempFile.toAbsolutePath().toString(),
                    companyId
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
            // Удаляем временный файл
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
