package com.example.model.dto.response;

import com.example.model.Client;
import com.example.model.enums.ClientSource;
import com.example.model.enums.ClientType;
import lombok.Data;

import java.util.List;
import java.util.stream.Collectors;

@Data
public class ClientWithOrdersResponse {
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String phone;
    private ClientType clientType;
    private ClientSource clientSource;
    private String notes;
    private List<OrderClientDto> orders;

    public ClientWithOrdersResponse(Client client) {
        this.id = client.getId();
        this.firstName = client.getFirstName();
        this.lastName = client.getLastName();
        this.email = client.getEmail();
        this.phone = client.getPhone();
        this.clientType = client.getClientType();
        this.clientSource = client.getClientSource();
        this.notes = client.getNotes();
        this.orders = client.getOrders()
                .stream()
                .map(OrderClientDto::new)
                .collect(Collectors.toList());
    }
}
