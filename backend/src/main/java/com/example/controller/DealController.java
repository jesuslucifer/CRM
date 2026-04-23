package com.example.controller;

import com.example.model.Deal;
import com.example.model.dto.request.update.DealUpdateRequest;
import com.example.model.dto.response.DealDto;
import com.example.model.dto.response.SuccessResponse;
import com.example.service.CompanyService;
import com.example.service.DealService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/deal/{dealId}")
public class DealController {
    private final DealService dealService;
    private final CompanyService companyService;

    @GetMapping
    public ResponseEntity<?> get(@PathVariable Long dealId) {
        return ResponseEntity.ok(
                dealService.getById(dealId));
    }

    @PutMapping
    public ResponseEntity<?> update(
            @PathVariable Long dealId,
            @RequestBody DealUpdateRequest request) {

        Deal deal = dealService.update(dealId, request);

        return ResponseEntity.ok(new DealDto(deal));
    }

    @DeleteMapping
    public ResponseEntity<?> remove(@PathVariable Long dealId) {
        companyService.removeDeal(dealId);

        return ResponseEntity.ok(new SuccessResponse(
                "Сделка удалена",
                HttpStatus.OK
        ));
    }
}
