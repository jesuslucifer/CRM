package com.example.model.dto.request;

import com.example.model.enums.DealType;
import com.example.model.enums.PropertyStatus;
import com.example.model.enums.PropertyType;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class CreatePropertyRequest {
    private Long cadastralNumber;
    private String title;
    private String description;
    private PropertyType propertyType;
    private DealType dealType;
    private String address;
    private String city;
    private String district;
    private BigDecimal price;
    private BigDecimal salePrice;
    private BigDecimal area;
    private int rooms;
    private int floor;
    private int totalFloors;
    private int yearBuilt;
    private PropertyStatus propertyStatus;
}
