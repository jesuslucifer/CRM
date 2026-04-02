package com.example.repository;

import com.example.model.Deal;
import com.example.model.dto.request.DealUpdateRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DealRepository extends JpaRepository<Deal, Long> {
    boolean existsByCompanyIdAndAgentIdAndPropertyIdAndClientId(
            Long companyId, Long agentId, Long propertyId, Long clientId);
}
