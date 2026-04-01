package com.example.controller;

import com.example.model.*;
import com.example.model.dto.request.DealCreateRequest;
import com.example.model.dto.request.DealUpdateRequest;
import com.example.model.dto.response.DealDto;
import com.example.model.dto.response.SuccessResponse;
import com.example.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/company/{id}")
public class CompanyDealController {
    private final CompanyService companyService;
    private final ClientService clientService;
    private final PropertyService propertyService;
    private final UserService userService;
    private final DealService dealService;

    @PostMapping("/deal/create")
    public ResponseEntity<?> createDeal(
            @PathVariable Long id,
            @RequestBody DealCreateRequest request) {
        Company company = companyService.getById(id);
        Client client = clientService.getById(request.getClientId());
        Property property = propertyService.getById(request.getPropertyId());
        User agent = userService.getById(request.getAgentId());

        Deal deal = Deal.builder()
                .company(company)
                .client(client)
                .property(property)
                .agent(agent)
                .status(request.getStatus())
                .price(request.getPrice())
                .build();

        dealService.create(deal);

        company.addDeal(deal);
        client.addDeal(deal);
        agent.addDeal(deal);

        return ResponseEntity.ok(new SuccessResponse(
                "Сделка создана",
                HttpStatus.OK
        ));
    }

    @PutMapping("/deal/{dealId}")
    public ResponseEntity<?> update(
            @PathVariable Long id,
            @PathVariable Long dealId,
            @RequestBody DealUpdateRequest request) {

        Deal deal = dealService.update(id, dealId, request);

        return ResponseEntity.ok(new DealDto(deal));
    }

}
