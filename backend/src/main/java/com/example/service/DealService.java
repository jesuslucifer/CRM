package com.example.service;

import com.example.model.Deal;
import com.example.model.dto.request.update.DealUpdateRequest;

public interface DealService {
    Deal create(Deal deal);
    Deal update(Long dealId, DealUpdateRequest request);
    Deal getById(Long id);
}
