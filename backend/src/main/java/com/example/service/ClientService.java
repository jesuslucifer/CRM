package com.example.service;

import com.example.model.Client;

public interface ClientService {
    Client save(Client client);
    Client create(Client client);
    Client getById(Long id);
}
