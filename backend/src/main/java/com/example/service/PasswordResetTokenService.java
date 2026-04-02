package com.example.service;

import com.example.model.PasswordResetToken;
import com.example.model.User;

public interface PasswordResetTokenService {
    PasswordResetToken create(User user);
    PasswordResetToken getPasswordResetToken(String token);
    void deletePasswordResetToken(String token);
    void deletePasswordResetTokenByUser(User user);
}
