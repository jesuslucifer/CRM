package com.example.service.impl;

import com.example.exception.CompanyNotFoundException;
import com.example.exception.EmailAlreadyExistsException;
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
        return clientRepository.save(client);
    }

    @Override
    public Client create(Client client) {
        if (clientRepository.existsByEmail(client.getEmail())) {
            throw new EmailAlreadyExistsException();
        }

        if (clientRepository.existsByPhone(client.getPhone())) {
            throw new EmailAlreadyExistsException(); //TODO EXCEPTION
        }

        return save(client);
    }

    @Override
    public Client getById(Long id) {
        return clientRepository.findById(id)
                .orElseThrow(CompanyNotFoundException::new); //TODO EXCEPTION
    }
}
