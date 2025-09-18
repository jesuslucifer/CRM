package com.example.service.impl;

import com.example.model.Token;
import com.example.repository.TokenRepository;
import com.example.service.TokenService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import com.example.model.User;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class TokenServiceImpl implements TokenService {
    private final TokenRepository tokenRepository;

    @Override
    public void saveToken(String refreshToken, User user) {
        Token token = new Token();

        token.setRefreshToken(refreshToken);

        token.setUser(user);

        tokenRepository.save(token);
    }

    @Override
    public void removeToken(User user) {
        List<Token> tokens = tokenRepository.findAllByUserId(user.getId());

        tokens.forEach(token -> token.setAvailable(false));

        tokenRepository.saveAll(tokens);
    }
}
