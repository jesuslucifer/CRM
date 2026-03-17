package com.example.controller;

import com.example.model.Client;
import com.example.model.dto.request.ClientCreateRequest;
import com.example.model.enums.ClientType;
import com.example.service.ClientService;
import com.example.service.CompanyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/client/")
public class ClientController {
    private final ClientService clientService;
    private final CompanyService companyService;

    public ResponseEntity<?> create(@RequestBody ClientCreateRequest request) {
        Client client = Client.builder()
                .company(companyService.getById(request.getCompanyId()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phone(request.getPhone())
                .email(request.getEmail())
                .clientType(request.getClientType())
                .clientSource(request.getClientSource())
                .build();


    }
}
