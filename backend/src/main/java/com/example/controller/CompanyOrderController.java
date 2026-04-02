package com.example.controller;

import com.example.model.Client;
import com.example.model.Company;
import com.example.model.Order;
import com.example.model.dto.request.OrderCreateRequest;
import com.example.model.dto.response.OrderDto;
import com.example.service.ClientService;
import com.example.service.CompanyService;
import com.example.service.OrderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/company/{companyId}/orders")
@RequiredArgsConstructor
public class CompanyOrderController {
    private final CompanyService companyService;
    private final OrderService orderService;
    private final ClientService clientService;

    @GetMapping
    public ResponseEntity<?> getAll(@PathVariable Long companyId) {
        return ResponseEntity.ok(
                companyService.getOrders(companyId));
    }

    @PostMapping
    public ResponseEntity<?> create(
            @PathVariable Long companyId,
            @RequestBody OrderCreateRequest request) {
        Company company = companyService.getById(companyId);
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
}
