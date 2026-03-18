package com.example.model.dto.response;

import com.example.model.Client;
import com.example.model.enums.ClientSource;
import com.example.model.enums.ClientType;
import lombok.Data;

@Data
public class ClientDto {
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String phone;
    private ClientType clientType;
    private ClientSource clientSource;
    private String notes;

    public ClientDto(Client client) {
        this.id = client.getId();
        this.firstName = client.getFirstName();
        this.lastName = client.getLastName();
        this.email = client.getEmail();
        this.phone = client.getPhone();
        this.clientType = client.getClientType();
        this.clientSource = client.getClientSource();
        this.notes = client.getNotes();
    }
}
