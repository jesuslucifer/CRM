package com.example.model.dto.response;

import com.example.model.OrderProperty;
import com.example.model.enums.OrderPropertyStatus;
import lombok.Data;

import java.time.Instant;

@Data
public class OrderPropertyResponse {
    private Long id;
    private Long propertyId;
    private OrderPropertyStatus status;
    private Instant dateTime;
    private String description;

    public OrderPropertyResponse(OrderProperty orderProperty) {
        this.id = orderProperty.getId();
        this.propertyId = orderProperty.getProperty().getId();
        this.status = orderProperty.getStatus();
        this.dateTime = orderProperty.getDateTime();
        this.description = orderProperty.getDescription();
    }
}
