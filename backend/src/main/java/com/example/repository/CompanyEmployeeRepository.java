package com.example.repository;

import com.example.model.CompanyEmployee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CompanyEmployeeRepository extends JpaRepository<CompanyEmployee, Long> {
    boolean existsByCompanyIdAndUserId(Long companyId, Long userId);
}
