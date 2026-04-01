package com.example.model.dto.response;

import com.example.model.Deal;
import com.example.model.enums.DealStatus;
import lombok.Data;

import java.math.BigDecimal;
import java.time.Instant;

@Data
public class DealDto {
    private Long id;
    private ClientDto client;
    private PropertyResponse property;
    private UserMinimalDto agent;
    private DealStatus status;
    private BigDecimal price;
    private Instant createdAt;
    private Instant closedAt;

    public DealDto (Deal deal) {
        this.id = deal.getId();
        this.client = new ClientDto(deal.getClient());
        this.property = new PropertyResponse(deal.getProperty());
        this.agent = new UserMinimalDto(deal.getAgent());
        this.status = deal.getStatus();
        this.price = deal.getPrice();
        this.createdAt = deal.getCreatedAt();
        this.closedAt = deal.getClosedAt();
    }
}
