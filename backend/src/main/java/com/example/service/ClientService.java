package com.example.service;

import com.example.model.Client;
import com.example.model.dto.request.create.ClientCreateRequest;

public interface ClientService {
    Client save(Client client);
    Client create(Client client);
    Client getById(Long id);
    Client update(Long id, ClientCreateRequest request);
}
