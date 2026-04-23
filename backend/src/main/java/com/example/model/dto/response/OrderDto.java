package com.example.model.dto.response;

import com.example.model.Order;
import com.example.model.enums.DealType;
import com.example.model.enums.OrderStatus;
import com.example.model.enums.PropertyType;
import lombok.Data;

import java.util.List;
import java.util.stream.Collectors;

@Data
public class OrderDto {
    private Long id;
    private ClientDto client;
    private UserMinimalDto agent;
    private String city;
    private List<OrderPropertyResponse> properties;
    private PropertyType propertyType;
    private DealType dealType;
    private String description;
    private OrderStatus status;

    public OrderDto(Order order) {
        this.id = order.getId();
        this.client = new ClientDto(order.getClient());
        this.agent = new UserMinimalDto(order.getAgent());
        this.city = order.getCity();
        this.propertyType = order.getPropertyType();
        this.dealType = order.getDealType();
        this.description = order.getDescription();
        this.properties = order.getProperties()
                .stream()
                .map(OrderPropertyResponse::new)
                .collect(Collectors.toList());
        this.status = order.getStatus();
    }
}
