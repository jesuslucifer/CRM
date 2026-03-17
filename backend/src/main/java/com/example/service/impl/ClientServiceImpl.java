package com.example.service.impl;

import com.example.model.Client;
import com.example.repository.ClientRepository;
import com.example.service.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ClientServiceImpl implements ClientService {
    private final ClientRepository clientRepository;

    @Override
    public Client save(Client client) {
        clientRepository.save(client);
    }

    @Override
    public Client create(Client client) {
        if (client.getEmail() )
    }
}
