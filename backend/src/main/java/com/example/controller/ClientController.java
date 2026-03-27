package com.example.controller;

import com.example.model.dto.request.ClientCreateRequest;
import com.example.model.dto.response.ClientDto;
import com.example.model.dto.response.ClientWithOrdersResponse;
import com.example.service.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/client/")
public class ClientController {
    private final ClientService clientService;

    @RequestMapping("/{id}")
    public ResponseEntity<?> getClient(@PathVariable Long id) {
        return ResponseEntity.ok(new ClientWithOrdersResponse(clientService.getById(id)));
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateClient(@PathVariable Long id,
                                          @RequestBody ClientCreateRequest request) {
        return ResponseEntity.ok(new ClientDto(clientService.update(id, request)));
    }
}
