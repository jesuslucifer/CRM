package com.example.service.impl;

import com.example.exception.EmployeeAlreadyExistsInCompanyException;
import com.example.exception.IdNotFoundException;
import com.example.model.Property;
import com.example.model.dto.request.CreatePropertyRequest;
import com.example.repository.PropertyRepository;
import com.example.service.PropertyService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@Transactional
@RequiredArgsConstructor
public class PropertyServiceImpl implements PropertyService {
    private final PropertyRepository propertyRepository;

    @Override
    public Property save(Property property) {
        return propertyRepository.save(property);
    }

    @Override
    public Property create(Property property) {
        if (propertyRepository.existsByCadastralNumberAndCompanyId(property.getCadastralNumber(), property.getCompany().getId())) {
            throw new EmployeeAlreadyExistsInCompanyException(); //TODO: EXCEPTION
        }

        return save(property);
    }

    @Override
    public Property update(Long id, CreatePropertyRequest request) {
        Property property = propertyRepository.findById(id)
                .orElseThrow(IdNotFoundException::new); //TODO: EXCEPTION

        property.setTitle(request.getTitle());
        property.setDescription(request.getDescription());
        property.setPropertyType(request.getPropertyType());
        property.setDealType(request.getDealType());
        property.setAddress(request.getAddress());
        property.setCity(request.getCity());
        property.setDistrict(request.getDistrict());
        property.setPrice(request.getPrice());
        property.setSalePrice(request.getSalePrice());
        property.setArea(request.getArea());
        property.setRooms(request.getRooms());
        property.setFloor(request.getFloor());
        property.setTotalFloors(request.getTotalFloors());
        property.setYearBuilt(request.getYearBuilt());
        property.setStatus(property.getStatus());

        return propertyRepository.save(property);
    }

    @Override
    public Property getById(Long id) {
        return propertyRepository.findById(id)
                .orElseThrow(IdNotFoundException::new); //TODO: EXCEPTION
    }

}
