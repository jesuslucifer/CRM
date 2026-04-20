package com.example.service.impl;

import com.example.exception.PropertyNotFoundException;
import com.example.model.Order;
import com.example.model.OrderProperty;
import com.example.model.Property;
import com.example.model.dto.request.OrderCreateRequest;
import com.example.model.dto.request.OrderPropertyUpdateRequest;
import com.example.model.enums.OrderPropertyStatus;
import com.example.model.enums.OrderStatus;
import com.example.repository.OrderRepository;
import com.example.service.OrderPropertyService;
import com.example.service.OrderService;
import com.example.service.PropertyService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OrderServiceImpl implements OrderService {
    private final OrderRepository orderRepository;
    private final PropertyService propertyService;
    private final OrderPropertyService orderPropertyService;

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
        order.setStatus(request.getStatus());


        return save(order);
    }

    @Override
    public Order getById(Long id) {
        return orderRepository.findById(id)
                .orElseThrow(PropertyNotFoundException::new); //TODO EXCEPTION
    }

    @Override
    public Order addProperty(Long orderId, Long propertyId) {
        Order order = getById(orderId);

        Property property = propertyService.getById(propertyId);

        OrderProperty orderProperty = OrderProperty.builder()
                .order(order)
                .property(property)
                .status(OrderPropertyStatus.SELECTION)
                .build();

        order.setStatus(OrderStatus.SELECTION);

        order.addProperty(orderPropertyService.save(orderProperty));

        return save(order);
    }

    @Override
    public Order removeProperty(Long orderId, Long propertyId) {
        Order order = getById(orderId);

        Property property = propertyService.getById(propertyId);

        OrderProperty orderProperty = orderPropertyService.getByOrderIdAndPropertyId(propertyId, orderId);

        order.removeProperty(orderProperty);

        return save(order);
    }

    @Override
    public Order updateOrderProperty(Long propertyId, Long orderId, OrderPropertyUpdateRequest orderPropertyUpdateRequest) {
        orderPropertyService.update(propertyId, orderId, orderPropertyUpdateRequest);

        Order order = getById(orderId);

        if (orderPropertyUpdateRequest.getStatus() == OrderPropertyStatus.SHOW_OFFLINE ||
        orderPropertyUpdateRequest.getStatus() == OrderPropertyStatus.SHOW_ONLINE) {

            order.setStatus(OrderStatus.SHOW);
        }

        return save(order);
    }
}
