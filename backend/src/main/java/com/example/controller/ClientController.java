package com.example.controller;

import com.example.model.dto.response.ClientWithOrdersResponse;
import com.example.service.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/client/")
public class ClientController {
    private final ClientService clientService;

    @RequestMapping("/{id}")
    public ResponseEntity<?> getClient(@PathVariable Long id) {
        return ResponseEntity.ok(new ClientWithOrdersResponse(clientService.getById(id)));
    }
}
