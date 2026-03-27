package com.example.model.dto.response;

import com.example.model.Order;
import com.example.model.enums.DealType;
import com.example.model.enums.PropertyType;
import lombok.Data;

@Data
public class OrderClientDto {
    private Long id;
    private String city;
    private PropertyType propertyType;
    private DealType dealType;
    private String description;

    public OrderClientDto(Order order) {
        this.id = order.getId();
        this.city = order.getCity();
        this.propertyType = order.getPropertyType();
        this.dealType = order.getDealType();
        this.description = order.getDescription();
    }
}
