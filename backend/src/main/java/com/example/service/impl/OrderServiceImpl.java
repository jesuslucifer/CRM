package com.example.service.impl;

import com.example.exception.PropertyNotFoundException;
import com.example.model.*;
import com.example.model.dto.request.OrderCreateRequest;
import com.example.model.dto.request.OrderPropertyUpdateRequest;
import com.example.model.enums.DealStatus;
import com.example.model.enums.OrderPropertyStatus;
import com.example.model.enums.OrderStatus;
import com.example.repository.OrderRepository;
import com.example.security.SecurityUtil;
import com.example.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class OrderServiceImpl implements OrderService {
    private final OrderRepository orderRepository;
    private final PropertyService propertyService;
    private final OrderPropertyService orderPropertyService;
    private final DealService dealService;
    private final UserService userService;

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
        addSingleProperty(order, propertyId);
        return save(order);
    }

    @Override
    public Order addProperties(Long orderId, List<Long> propertyIds) {
        Order order = getById(orderId);
        for (Long propertyId : propertyIds) {
            addSingleProperty(order, propertyId);
        }
        return save(order);
    }

    private void addSingleProperty(Order order, Long propertyId) {
        Property property = propertyService.getById(propertyId);

        if (orderPropertyService.existsByOrderIdAndPropertyId(order.getId(), propertyId)) {
            log.info("Property {} already exist in order {}", propertyId, order.getId());
            return;
        }

        OrderProperty orderProperty = OrderProperty.builder()
                .order(order)
                .property(property)
                .status(OrderPropertyStatus.SELECTION)
                .build();

        order.addProperty(orderPropertyService.save(orderProperty));
        log.info("Add property {} to order {}", propertyId, order.getId());

        updateOrderStatusToSelection(order);
    }

    private void updateOrderStatusToSelection(Order order) {
        if (order.getStatus() != OrderStatus.SELECTION) {
            order.setStatus(OrderStatus.SELECTION);
            log.info("Order status changed to SELECTION for order {}", order.getId());
        }
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

        switch (orderPropertyUpdateRequest.getStatus()) {
            case SHOW_OFFLINE, SHOW_ONLINE -> order.setStatus(OrderStatus.SHOW);

            case DEAL -> {
                order.setStatus(OrderStatus.DEAL);

                User user = userService.getById(SecurityUtil.getCurrentUser().getId());

                Deal deal = Deal.builder()
                        .company(order.getCompany())
                        .client(order.getClient())
                        .property(propertyService.getById(propertyId))
                        .agent(user)
                        .status(DealStatus.NEW)
                        .createdAt(Instant.now())
                        .build();

                dealService.create(deal);
            }
        }

        return save(order);
    }
}
