package com.example.model.dto.response;

import com.example.model.PropertyImage;
import lombok.Data;

@Data
public class ImageDto {
    private Long id;
    private String url;
    private boolean isMain;

    public ImageDto(PropertyImage image) {
        this.id = image.getId();
        this.url = "/api/files/" + image.getStoredFilename();
        this.isMain = image.getIsMain();
    }
}
