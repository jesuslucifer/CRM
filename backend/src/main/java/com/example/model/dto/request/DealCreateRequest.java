package com.example.model.dto.request;

import com.example.model.enums.DealStatus;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class DealCreateRequest {
    private Long companyId;
    private Long clientId;
    private Long propertyId;
    private Long agentId;
    private DealStatus status;
    private BigDecimal price;
}
