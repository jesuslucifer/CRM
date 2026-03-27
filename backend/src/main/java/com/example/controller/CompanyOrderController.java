package com.example.controller;

import com.example.model.Client;
import com.example.model.Company;
import com.example.model.Order;
import com.example.model.dto.request.OrderCreateRequest;
import com.example.model.dto.response.OrderDto;
import com.example.model.dto.response.SuccessResponse;
import com.example.service.ClientService;
import com.example.service.CompanyService;
import com.example.service.OrderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/company/{id}")
@RequiredArgsConstructor
public class CompanyOrderController {
    private final CompanyService companyService;
    private final OrderService orderService;
    private final ClientService clientService;

    @GetMapping("/orders")
    public ResponseEntity<?> getOrders(@PathVariable Long id) {
        return ResponseEntity.ok(companyService.getOrders(id));
    }

    @PostMapping("/order/create")
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

    @DeleteMapping("/{orderId}/order")
    public ResponseEntity<?> removeOrder(
            @PathVariable Long id,
            @PathVariable Long orderId) {
        companyService.removeOrder(id, orderId);

        return ResponseEntity.ok(new SuccessResponse(
                "Заявка удалена",
                HttpStatus.OK
        ));
    }
}
