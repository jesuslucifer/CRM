package com.example.service.impl;

import com.example.exception.*;
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
        if (clientRepository.existsByEmailAndCompanyId(
                client.getEmail(), client.getCompany().getId())) {
            throw new EmailAlreadyExistsException();
        }

        if (clientRepository.existsByPhoneAndCompanyId(
                client.getPhone(), client.getCompany().getId())) {
            throw new PhoneAlreadyExistsException();
        }

        if (clientRepository.existsByPhoneAndEmailAndCompanyId(
                client.getEmail(), client.getPhone(), client.getCompany().getId())) {
            throw new ClientAlreadyExistsException();
        }

        return save(client);
    }

    @Override
    public Client getById(Long id) {
        return clientRepository.findById(id)
                .orElseThrow(ClientNotFoundException::new);
    }
}
