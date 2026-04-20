package com.example.service;

import com.example.model.OrderProperty;
import com.example.model.dto.request.OrderPropertyUpdateRequest;

public interface OrderPropertyService {
    OrderProperty save(OrderProperty orderProperty);
    OrderProperty create(OrderProperty orderProperty);
    OrderProperty getById(Long orderPropertyId);
    OrderProperty getByOrderIdAndPropertyId(Long propertyId, Long orderId);
    OrderProperty update(Long propertyId, Long orderId, OrderPropertyUpdateRequest orderPropertyUpdateRequest);
}
