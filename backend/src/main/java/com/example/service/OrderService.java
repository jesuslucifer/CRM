package com.example.service;

import com.example.model.Order;

public interface OrderService {
    Order save(Order order);
    Order create(Order order);
}
