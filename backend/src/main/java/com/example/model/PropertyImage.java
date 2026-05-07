package com.example.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "property-images")
public class PropertyImage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "property_id")
    private Property property;

    @Column(name = "file_path")
    private String filePath;

    @Column(name = "original-filename")
    private String originalFilename;

    @Column(name = "stored-filename")
    private String storedFilename;

    @Column(name = "file-size")
    private Long fileSize;

    @Column(name = "content-type")
    private String contentType;

    @Column(name = "sort-order")
    private Long sortOrder;

    @Column(name = "is-main")
    private Boolean isMain;

    @Column(name = "created-at")
    private Instant createdAt;

}
