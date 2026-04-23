package com.example.controller;

import com.example.model.Client;
import com.example.model.Company;
import com.example.model.dto.request.create.ClientCreateRequest;
import com.example.model.dto.response.ClientDto;
import com.example.service.ClientService;
import com.example.service.CompanyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/company/{companyId}/clients")
@RequiredArgsConstructor
public class CompanyClientController {
    private final CompanyService companyService;
    private final ClientService clientService;

    @GetMapping
    public ResponseEntity<?> getAll(@PathVariable Long companyId) {
        return ResponseEntity.ok(
                companyService.getClients(companyId));
    }

    @PostMapping
    public ResponseEntity<?> create(
            @PathVariable Long companyId,
            @RequestBody ClientCreateRequest request) {
        Company company = companyService.getById(companyId);

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
}
