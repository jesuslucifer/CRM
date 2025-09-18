package com.example.service;

import com.example.model.User;

public interface TokenService {
    void saveToken(String accessToken, String refreshToken, User user);
}
