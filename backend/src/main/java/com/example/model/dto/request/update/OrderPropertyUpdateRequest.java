package com.example.model.dto.request.update;

import com.example.model.enums.OrderPropertyStatus;
import lombok.Data;

@Data
public class OrderPropertyUpdateRequest {
    private OrderPropertyStatus status;
}
