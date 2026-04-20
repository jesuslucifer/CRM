package com.example.controller;

import com.example.model.dto.request.OrderCreateRequest;
import com.example.model.dto.request.OrderPropertyUpdateRequest;
import com.example.model.dto.response.OrderDto;
import com.example.model.dto.response.SuccessResponse;
import com.example.service.CompanyService;
import com.example.service.OrderService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/order/{orderId}")
public class OrderController {
    private final CompanyService companyService;
    private final OrderService orderService;

    @GetMapping
    public ResponseEntity<?> get(@PathVariable Long orderId) {
        return ResponseEntity.ok(
                new OrderDto(orderService.getById(orderId)));
    }

    @PutMapping
    public ResponseEntity<?> update(@PathVariable Long orderId,
                                    @RequestBody OrderCreateRequest request) {
        return ResponseEntity.ok(
                new OrderDto(orderService.update(orderId, request)));
    }

    @DeleteMapping
    public ResponseEntity<?> remove(@PathVariable Long orderId) {
        companyService.removeOrder(orderId);

        return ResponseEntity.ok(new SuccessResponse(
                "Заявка удалена",
                HttpStatus.OK
        ));
    }

    @PutMapping("/{propertyId}/property")
    public ResponseEntity<?> addProperty(@PathVariable Long orderId,
                                         @PathVariable Long propertyId) {
        return ResponseEntity.ok(
                new OrderDto(orderService.addProperty(orderId, propertyId)));
    }

    @DeleteMapping("/{propertyId}/property")
    public ResponseEntity<?> removeProperty(@PathVariable Long orderId,
                                         @PathVariable Long propertyId) {
        return ResponseEntity.ok(
                new OrderDto(orderService.removeProperty(orderId, propertyId)));
    }

    @PutMapping("/{propertyId}/order-property")
    public ResponseEntity<?> updateOrderProperty(@PathVariable Long orderId,
                                                 @PathVariable Long propertyId,
                                                 @RequestBody OrderPropertyUpdateRequest orderPropertyUpdateRequest) {
        return ResponseEntity.ok(
                new OrderDto(orderService.updateOrderProperty(propertyId, orderId, orderPropertyUpdateRequest))
        );
    }
}
