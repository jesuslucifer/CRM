package com.example.controller;

import com.example.model.dto.request.ClientCreateRequest;
import com.example.model.dto.response.ClientDto;
import com.example.model.dto.response.ClientWithOrdersResponse;
import com.example.model.dto.response.SuccessResponse;
import com.example.service.ClientService;
import com.example.service.CompanyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/client/{clientId}")
public class ClientController {
    private final ClientService clientService;
    private final CompanyService companyService;

    @GetMapping
    public ResponseEntity<?> get(@PathVariable Long clientId) {
        return ResponseEntity.ok(new ClientWithOrdersResponse(clientService.getById(clientId)));
    }

    @PutMapping
    public ResponseEntity<?> update(@PathVariable Long clientId,
                                          @RequestBody ClientCreateRequest request) {
        return ResponseEntity.ok(
                new ClientDto(clientService.update(clientId, request)));
    }

    @DeleteMapping
    public ResponseEntity<?> remove(@PathVariable Long clientId) {
        companyService.removeClient(clientId);

        return ResponseEntity.ok(new SuccessResponse(
                "Клиент удалена",
                HttpStatus.OK
        ));
    }
}
