package com.example.service.impl;

import com.example.exception.PropertyNotFoundException;
import com.example.model.OrderProperty;
import com.example.model.dto.request.OrderPropertyUpdateRequest;
import com.example.repository.OrderPropertyRepository;
import com.example.service.OrderPropertyService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@Transactional
@RequiredArgsConstructor
public class OrderPropertyServiceImpl implements OrderPropertyService {
    private final OrderPropertyRepository orderPropertyRepository;

    @Override
    public OrderProperty save(OrderProperty orderProperty) {
        return orderPropertyRepository.save(orderProperty);
    }

    @Override
    public OrderProperty create(OrderProperty orderProperty) {
        return save(orderProperty);
    }

    @Override
    public OrderProperty getById(Long orderPropertyId) {
        return orderPropertyRepository.findById(orderPropertyId)
                .orElseThrow(PropertyNotFoundException::new); // TODO: EXCEPTION
    }

    @Override
    public OrderProperty getByOrderIdAndPropertyId(Long propertyId, Long orderId) {
        return orderPropertyRepository.findByOrderIdAndPropertyId(orderId, propertyId)
                .orElseThrow(PropertyNotFoundException::new); // TODO: EXCEPTION
    }

    @Override
    public OrderProperty update(Long propertyId, Long orderId, OrderPropertyUpdateRequest orderPropertyUpdateRequest) {
        OrderProperty orderProperty = getByOrderIdAndPropertyId(propertyId, orderId);

        orderProperty.setStatus(orderPropertyUpdateRequest.getStatus());

        return save(orderProperty);
    }

    @Override
    public boolean existsByOrderIdAndPropertyId(Long orderId, Long propertyId) {
        return orderPropertyRepository.existsByOrderIdAndPropertyId(orderId, propertyId);
    }
}
