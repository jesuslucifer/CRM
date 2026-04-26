package com.example.controller;

import com.example.model.PropertyImage;
import com.example.service.PropertyImageService;
import com.example.service.PropertyService;
import jakarta.annotation.Resource;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.UrlResource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/files")
public class FileController {
    private final PropertyService propertyService;
    private final PropertyImageService propertyImageService;

    @GetMapping("/{filename}")
    public ResponseEntity<?> getFile(@PathVariable String filename) {
        PropertyImage image = propertyImageService.findByStoredFilename(filename);

        Path filePath = Path.of(image.getFilePath());

        if (!Files.exists(filePath)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND); //TODO: EXCEPTION
        }
        UrlResource resource;

        try {
            resource = new UrlResource(filePath.toUri());
        } catch (MalformedURLException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR); //TODO: EXCEPTION
        }

        MediaType mediaType;

        try {
            String mimeType = Files.probeContentType(filePath);
            mediaType = mimeType != null ?
                    MediaType.parseMediaType(mimeType) :
                    MediaType.APPLICATION_OCTET_STREAM;
        } catch (IOException e) {
            mediaType = MediaType.APPLICATION_OCTET_STREAM;
        }

        return ResponseEntity.ok()
                .contentType(mediaType)
                .cacheControl(CacheControl.maxAge(7, TimeUnit.DAYS))
                .body(resource);
    }
}
