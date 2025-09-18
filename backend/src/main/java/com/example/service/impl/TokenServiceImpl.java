package com.example.service.impl;

import com.example.model.Token;
import com.example.repository.TokenRepository;
import com.example.service.TokenService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import com.example.model.User;

@Service
@RequiredArgsConstructor
@Transactional
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepository;

    public void saveToken(String accessToken, String refreshToken, User user) {
        Token token = new Token();

        token.setRefreshToken(refreshToken);

        token.setAccessToken(accessToken);

        token.setUser(user);

        tokenRepository.save(token);
    }
}
