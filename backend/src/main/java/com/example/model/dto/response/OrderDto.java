package com.example.model.dto.response;

import com.example.model.Order;
import com.example.model.Property;
import com.example.model.enums.DealType;
import com.example.model.enums.PropertyType;
import lombok.Data;

import java.util.List;
import java.util.stream.Collectors;

@Data
public class OrderDto {
    private Long id;
    private ClientDto client;
    private String city;
    private List<PropertyResponse> properties;
    private PropertyType propertyType;
    private DealType dealType;
    private String description;

    public OrderDto(Order order) {
        this.id = order.getId();
        this.client = new ClientDto(order.getClient());
        this.city = order.getCity();
        this.propertyType = order.getPropertyType();
        this.dealType = order.getDealType();
        this.description = order.getDescription();
        this.properties = order.getProperties()
                .stream()
                .map(PropertyResponse::new)
                .collect(Collectors.toList());
    }
}
