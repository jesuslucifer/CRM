package com.example.service;

import com.example.model.Deal;
import com.example.model.dto.request.DealUpdateRequest;

public interface DealService {
    Deal create(Deal deal);
    Deal update(Long companyId, Long dealId, DealUpdateRequest request);
    Deal getById(Long id);
}
