package com.example.service.impl;

import com.example.exception.PropertyAlreadyExistsException;
import com.example.model.Deal;
import com.example.repository.DealRepository;
import com.example.service.DealService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@Transactional
@RequiredArgsConstructor
public class DealServiceImpl implements DealService {
    private final DealRepository dealRepository;

    private Deal save(Deal deal) {
        return dealRepository.save(deal);
    }

    @Override
    public Deal create(Deal deal) {
        if (dealRepository.existsByCompanyIdAndAgentIdAndPropertyIdAndClientId(
                deal.getCompany().getId(),
                deal.getAgent().getId(),
                deal.getProperty().getId(),
                deal.getClient().getId()))
            throw new PropertyAlreadyExistsException(); //TODO EXCEPTION

        return save(deal);
    }
}
