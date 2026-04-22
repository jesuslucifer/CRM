package com.example.service;

import com.example.model.Order;
import com.example.model.dto.request.OrderCreateRequest;
import com.example.model.dto.request.OrderPropertyUpdateRequest;

import java.util.List;

public interface OrderService {
    Order save(Order order);
    Order create(Order order);
    Order update(Long orderId, OrderCreateRequest request);
    Order getById(Long id);
    Order addProperty(Long orderId, Long propertyId);
    Order addProperties(Long orderId, List<Long> propertyIds);
    Order removeProperty(Long orderId, Long propertyId);
    Order updateOrderProperty(Long propertyId, Long orderId, OrderPropertyUpdateRequest orderPropertyUpdateRequest);
}
