package com.example.repository;

import com.example.model.OrderProperty;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OrderPropertyRepository extends JpaRepository<OrderProperty, Long> {
    Optional<OrderProperty> findByOrderIdAndPropertyId(Long orderId, Long propertyId);
    boolean existsByOrderIdAndPropertyId(Long orderId, Long propertyId);
}
