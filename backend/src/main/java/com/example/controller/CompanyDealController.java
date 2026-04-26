package com.example.controller;

import com.example.model.*;
import com.example.model.dto.request.create.DealCreateRequest;
import com.example.model.dto.response.SuccessResponse;
import com.example.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/company/{companyId}/deals")
public class CompanyDealController {
    private final CompanyService companyService;
    private final ClientService clientService;
    private final PropertyService propertyService;
    private final UserService userService;
    private final DealService dealService;

    @GetMapping
    public ResponseEntity<?> getAll(@PathVariable Long companyId) {
        return ResponseEntity.ok(
                companyService.getDeals(companyId));
    }

    @PostMapping
    public ResponseEntity<?> create(
            @PathVariable Long companyId,
            @RequestBody DealCreateRequest request) {
        Company company = companyService.getById(companyId);
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

}
