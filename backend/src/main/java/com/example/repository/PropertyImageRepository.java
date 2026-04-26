package com.example.repository;

import com.example.model.PropertyImage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PropertyImageRepository extends JpaRepository<PropertyImage, Long> {
    @Query("SELECT COALESCE(MAX(pi.sortOrder), 0) FROM PropertyImage pi WHERE pi.property.id = :propertyId")
    Long findMaxSortOrderByPropertyId(@Param("propertyId") Long propertyId);
    Optional<PropertyImage> findByStoredFilename(String filename);
}
