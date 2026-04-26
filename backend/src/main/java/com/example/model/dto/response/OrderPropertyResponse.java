package com.example.model.dto.response;

import com.example.model.OrderProperty;
import com.example.model.enums.OrderPropertyStatus;
import lombok.Data;

@Data
public class OrderPropertyResponse {
    private Long id;
    private Long propertyId;
    private OrderPropertyStatus status;

    public OrderPropertyResponse(OrderProperty orderProperty) {
        this.id = orderProperty.getId();
        this.propertyId = orderProperty.getProperty().getId();
        this.status = orderProperty.getStatus();
    }
}
