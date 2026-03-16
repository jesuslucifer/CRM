package com.example.repository;

import com.example.model.Property;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PropertyRepository extends JpaRepository<Property, Long> {
    boolean existsByCadastralNumberAndCompanyId(Long cadastralNumber, Long companyId);
    Property findById(long id);
    List<Property> findAllByCadastralNumberInAndCompanyId(List<Long> cadastralNumbers, Long companyId);
}
