package com.example.repository;

import com.example.model.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientRepository extends JpaRepository<Client, Long> {
    boolean existsByEmailAndCompanyId(String email, Long companyId);
    boolean existsByPhoneAndCompanyId(String phone, Long companyId);
    boolean existsByPhoneAndEmailAndCompanyId(String email, String phone, Long companyId);
}
