package com.example.model.dto.request.update;

import com.example.model.enums.DealStatus;
import lombok.Data;

import java.math.BigDecimal;
import java.time.Instant;

@Data
public class DealUpdateRequest {
    private Long companyId;
    private Long agentId;
    private DealStatus status;
    private BigDecimal price;
    private Instant closedAt;
}
