package com.example.service;

import com.example.model.User;
import org.springframework.stereotype.Service;

@Service
public interface EmailService {
    void send(String to, String subject, String body);
    void sendPasswordResetToken(String email, String contextPath, User user, String token);
}
