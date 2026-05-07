package com.example.model.dto.request.update;

import com.example.model.enums.OrderPropertyStatus;
import lombok.Data;

import java.time.Instant;

@Data
public class OrderPropertyUpdateRequest {
    private OrderPropertyStatus status;
    private Instant dateTime;
    private String description;
}
