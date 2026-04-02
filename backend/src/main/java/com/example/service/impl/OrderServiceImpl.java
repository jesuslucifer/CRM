package com.example.service.impl;

import com.example.exception.PropertyNotFoundException;
import com.example.model.Order;
import com.example.model.dto.request.OrderCreateRequest;
import com.example.repository.OrderRepository;
import com.example.service.OrderService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OrderServiceImpl implements OrderService {
    private final OrderRepository orderRepository;

    @Override
    public Order save(Order order) {
        return orderRepository.save(order);
    }

    @Override
    public Order create(Order order) {
        return save(order);
    }

    @Override
    public Order update(Long orderId, OrderCreateRequest request) {
        Order order = getById(orderId);

        order.setCity(request.getCity());
        order.setPropertyType(request.getPropertyType());
        order.setDealType(request.getDealType());
        order.setDescription(request.getDescription());

        return save(order);
    }

    @Override
    public Order getById(Long id) {
        return orderRepository.findById(id)
                .orElseThrow(PropertyNotFoundException::new); //TODO EXCEPTION
    }
}
