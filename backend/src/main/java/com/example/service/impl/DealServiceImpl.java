package com.example.service.impl;

import com.example.exception.CompanyNotFoundException;
import com.example.exception.PropertyAlreadyExistsException;
import com.example.model.Deal;
import com.example.model.dto.request.DealUpdateRequest;
import com.example.repository.DealRepository;
import com.example.service.DealService;
import com.example.service.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@Transactional
@RequiredArgsConstructor
public class DealServiceImpl implements DealService {
    private final DealRepository dealRepository;
    private final UserService userService;

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

    @Override
    public Deal getById(Long id) {
        return dealRepository.findById(id)
                .orElseThrow(CompanyNotFoundException::new); //TODO EXCEPTION
    }

    @Override
    public Deal update(Long dealId, DealUpdateRequest request) {
        Deal deal = getById(dealId);

        deal.setAgent(userService.getById(request.getAgentId()));
        deal.setPrice(request.getPrice());
        deal.setStatus(request.getStatus());
        deal.setClosedAt(request.getClosedAt());

        return save(deal);
    }
}
