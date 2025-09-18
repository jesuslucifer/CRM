package com.example.service;

import com.example.model.User;

public interface TokenService {
    void saveToken(String refreshToken, User user);
    void removeToken(User user);
}
