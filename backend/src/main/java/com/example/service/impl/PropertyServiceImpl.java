package com.example.service.impl;

import com.example.exception.*;
import com.example.model.*;
import com.example.model.dto.request.create.PropertyCreateRequest;
import com.example.model.enums.DealType;
import com.example.model.enums.PropertyStatus;
import com.example.model.enums.PropertyType;
import com.example.repository.PropertyRepository;
import com.example.service.LocalStorageService;
import com.example.service.PropertyService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class PropertyServiceImpl implements PropertyService {
    private final PropertyRepository propertyRepository;
    private final LocalStorageService localStorageService;

    @Override
    public Property save(Property property) {
        return propertyRepository.save(property);
    }

    @Override
    public Property create(Property property) {
        if (propertyRepository.existsByCadastralNumberAndCompanyId(property.getCadastralNumber(), property.getCompany().getId())) {
            throw new PropertyAlreadyExistsException();
        }

        Property createProperty = save(property);

        localStorageService.createPropertyDirectory(
                property.getId(), property.getCompany().getId());

        return createProperty;
    }

    @Override
    public Property update(Long id, PropertyCreateRequest request) {
        Property property = getById(id);

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

        return save(property);
    }

    @Override
    public Property getById(Long id) {
        return propertyRepository.findById(id)
                .orElseThrow(PropertyNotFoundException::new);
    }

    @Override
    public List<Property> importFromCsv(String fileName, Company company) {
        List<Property> importedProperties = new ArrayList<>();
        int createdCount = 0;
        int updatedCount = 0;
        int skippedCount = 0;

        try (Scanner sc = new Scanner(new File(fileName))) {
            if (sc.hasNextLine()) {
                sc.nextLine();
            }

            List<Long> cadastralNumbers = new ArrayList<>();
            List<String[]> csvRows = new ArrayList<>();

            while (sc.hasNextLine()) {
                String line = sc.nextLine().trim();
                if (line.isEmpty()) continue;

                String[] split = line.split(",");
                if (split.length >= 12) {
                    try {
                        Long cadastralNumber = Long.parseLong(split[0].trim());
                        cadastralNumbers.add(cadastralNumber);
                        csvRows.add(split);
                    } catch (NumberFormatException e) {
                        log.warn("Некорректный кадастровый номер в строке: {}", line);
                        skippedCount++;
                    }
                } else {
                    log.warn("Пропущена строка с недостаточным количеством полей: {}", line);
                    skippedCount++;
                }
            }

            List<Property> existingProperties = propertyRepository
                    .findAllByCadastralNumberInAndCompanyId(cadastralNumbers, company.getId());

            Map<Long, Property> propertyMap = existingProperties.stream()
                    .collect(Collectors.toMap(
                            Property::getCadastralNumber,
                            property -> property
                    ));

            for (String[] split : csvRows) {
                try {
                    Long cadastralNumber = Long.parseLong(split[0].trim());

                    if (propertyMap.containsKey(cadastralNumber)) {
                        Property existingProperty = propertyMap.get(cadastralNumber);
                        updatePropertyFromCsv(existingProperty, split);
                        importedProperties.add(existingProperty);
                        updatedCount++;
                    } else {
                        Property newProperty = toProperty(split, company);
                        importedProperties.add(newProperty);
                        createdCount++;
                    }
                } catch (Exception e) {
                    log.error("Ошибка при обработке строки: {}", String.join(",", split), e);
                    skippedCount++;
                }
            }

            // Сохраняем все изменения одним батчем
            if (!importedProperties.isEmpty()) {
                propertyRepository.saveAll(importedProperties);
            }

            log.info("Импорт завершен. Создано: {}, Обновлено: {}, Пропущено: {}",
                    createdCount, updatedCount, skippedCount);

        } catch (FileNotFoundException e) {
            log.error("Файл не найден: {}", fileName, e);
            throw new RuntimeException("Файл не найден: " + fileName, e);
        } catch (Exception e) {
            log.error("Ошибка при импорте CSV", e);
            throw new RuntimeException("Ошибка при импорте CSV", e);
        }

        return importedProperties;
    }

    @Override
    public Property addImage(Long id, MultipartFile file) {
        Property property = getById(id);

        if (file.isEmpty()) {
            throw new UploadFileIsEmptyException();
        }

        if (!file.getContentType().startsWith("image")) {
            throw new InvalidFileTypeException();
        }

        String filename = "property_" + property.getId() + "_" + property.getTitle();
        String fileUrl = localStorageService.uploadFile(file, filename);

        return save(property);
    }

    private Property toProperty(String[] split, Company company) {
        try {

            return Property.builder()
                    .cadastralNumber(Long.parseLong(split[0].trim()))
                    .title(split.length > 1 ? split[1].trim() : null)
                    .description(split.length > 2 ? split[2].trim() : null)
                    .propertyType(split.length > 3 && !split[3].trim().isEmpty()
                            ? PropertyType.valueOf(split[3].trim()) : null)
                    .dealType(split.length > 4 && !split[4].trim().isEmpty()
                            ? DealType.valueOf(split[4].trim()) : null)
                    .address(split.length > 5 ? split[5].trim() : null)
                    .salePrice(split.length > 6 && !split[6].trim().isEmpty()
                            ? new BigDecimal(split[6].trim()) : BigDecimal.ZERO)
                    .area(split.length > 7 && !split[7].trim().isEmpty()
                            ? new BigDecimal(split[7].trim()) : BigDecimal.ZERO)
                    .rooms(split.length > 8 && !split[8].trim().isEmpty()
                            ? Integer.parseInt(split[8].trim()) : 0)
                    .totalFloors(split.length > 9 && !split[9].trim().isEmpty()
                            ? Integer.parseInt(split[9].trim()) : 0)
                    .yearBuilt(split.length > 10 && !split[10].trim().isEmpty()
                            ? Integer.parseInt(split[10].trim()) : 0)
                    .status(split.length > 11 && !split[11].trim().isEmpty()
                            ? PropertyStatus.valueOf(split[11].trim()) : PropertyStatus.AVAILABLE)
                    .city(split.length > 12 && !split[12].trim().isEmpty()
                            ? split[12].trim() : null)
                    .price(split.length > 13 && !split[13].trim().isEmpty() ?
                            new BigDecimal(split[13].trim()) : BigDecimal.ZERO)
                    .district(split.length > 14 && !split[14].trim().isEmpty()
                            ? split[14].trim() : null)
                    .floor(split.length > 15 && !split[15].trim().isEmpty()
                            ? Integer.parseInt(split[15].trim()) : 0)

                    .company(company)
                    .build();
        } catch (Exception e) {
            log.error("Ошибка при парсинге строки в Property: {}", String.join(",", split), e);
            throw new IllegalArgumentException("Некорректные данные в CSV", e);
        }
    }

    private void updatePropertyFromCsv(Property property, String[] split) {
        try {
            if (split.length > 1) property.setTitle(split[1].trim());
            if (split.length > 2) property.setDescription(split[2].trim());
            if (split.length > 3 && !split[3].trim().isEmpty())
                property.setPropertyType(PropertyType.valueOf(split[3].trim()));
            if (split.length > 4 && !split[4].trim().isEmpty())
                property.setDealType(DealType.valueOf(split[4].trim()));
            if (split.length > 5) property.setAddress(split[5].trim());
            if (split.length > 6 && !split[6].trim().isEmpty())
                property.setSalePrice(new BigDecimal(split[6].trim()));
            if (split.length > 7 && !split[7].trim().isEmpty())
                property.setArea(new BigDecimal(split[7].trim()));
            if (split.length > 8 && !split[8].trim().isEmpty())
                property.setRooms(Integer.parseInt(split[8].trim()));
            if (split.length > 9 && !split[9].trim().isEmpty())
                property.setTotalFloors(Integer.parseInt(split[9].trim()));
            if (split.length > 10 && !split[10].trim().isEmpty())
                property.setYearBuilt(Integer.parseInt(split[10].trim()));
            if (split.length > 11 && !split[11].trim().isEmpty())
                property.setStatus(PropertyStatus.valueOf(split[11].trim()));
            if (split.length > 12 && !split[12].trim().isEmpty())
                property.setCity(split[12].trim());
            if (split.length > 13 && !split[13].trim().isEmpty())
                property.setPrice(new BigDecimal(split[13].trim()));
            if (split.length > 14 && !split[14].trim().isEmpty())
                property.setDistrict(split[14].trim());
            if (split.length > 15 && !split[15].trim().isEmpty())
                property.setFloor(Integer.parseInt(split[15].trim()));
        } catch (Exception e) {
            log.error("Ошибка при обновлении Property из CSV", e);
            throw new IllegalArgumentException("Некорректные данные в CSV", e);
        }
    }
}
