package com.example.model.dto.request.create;

import com.example.model.enums.DealType;
import com.example.model.enums.OrderStatus;
import com.example.model.enums.PropertyType;
import lombok.Data;

@Data
public class OrderCreateRequest {
    private Long clientId;
    private String city;
    private PropertyType propertyType;
    private DealType dealType;
    private String description;
    private OrderStatus status;
}
