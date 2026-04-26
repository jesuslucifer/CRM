package com.example.model.dto.request.create;

import com.example.model.enums.ClientSource;
import com.example.model.enums.ClientType;
import lombok.Data;

@Data
public class ClientCreateRequest {
    private String firstName;
    private String lastName;
    private String phone;
    private String email;
    private ClientType clientType;
    private ClientSource clientSource;
    private String notes;
}
