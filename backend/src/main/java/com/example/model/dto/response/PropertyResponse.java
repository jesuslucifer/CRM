package com.example.model.dto.response;

import com.example.model.*;
import com.example.model.enums.DealType;
import com.example.model.enums.PropertyStatus;
import com.example.model.enums.PropertyType;
import lombok.Data;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

@Data
public class PropertyResponse {
    private Long id;
    private Long cadastralNumber;
    private CompanyMinimalDto company;
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
    private List<ImageDto> images;

    public PropertyResponse(Property property, Company company) {
        this.id = property.getId();
        this.cadastralNumber = property.getCadastralNumber();
        this.company = new CompanyMinimalDto(company);
        this.title = property.getTitle();
        this.description = property.getDescription();
        this.propertyType = property.getPropertyType();
        this.dealType = property.getDealType();
        this.address = property.getAddress();
        this.city = property.getCity();
        this.district = property.getDistrict();
        this.price = property.getPrice();
        this.salePrice = property.getSalePrice();
        this.area = property.getArea();
        this.rooms = property.getRooms();
        this.floor = property.getFloor();
        this.totalFloors = property.getTotalFloors();
        this.yearBuilt = property.getYearBuilt();
        this.propertyStatus = property.getStatus();
    }

    public PropertyResponse(Property property) {
        this.id = property.getId();
        this.cadastralNumber = property.getCadastralNumber();
        this.title = property.getTitle();
        this.description = property.getDescription();
        this.propertyType = property.getPropertyType();
        this.dealType = property.getDealType();
        this.address = property.getAddress();
        this.city = property.getCity();
        this.district = property.getDistrict();
        this.price = property.getPrice();
        this.salePrice = property.getSalePrice();
        this.area = property.getArea();
        this.rooms = property.getRooms();
        this.floor = property.getFloor();
        this.totalFloors = property.getTotalFloors();
        this.yearBuilt = property.getYearBuilt();
        this.propertyStatus = property.getStatus();
        this.images = property.getImages()
                .stream()
                .map(ImageDto::new)
                .collect(Collectors.toList());
    }
}
