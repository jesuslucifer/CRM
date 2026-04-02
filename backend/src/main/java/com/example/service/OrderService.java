package com.example.service;

import com.example.model.Order;
import com.example.model.dto.request.OrderCreateRequest;

public interface OrderService {
    Order save(Order order);
    Order create(Order order);
    Order update(Long orderId, OrderCreateRequest request);
    Order getById(Long id);
}
