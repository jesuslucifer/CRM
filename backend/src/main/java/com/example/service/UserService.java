package com.example.service;

import com.example.model.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService {
    User save(User user);
    User create(User user);
    User getByUsernameOrEmail(String username, String email);
    User getByUsername(String username);
    UserDetailsService userDetailsService();
    User getCurrentUser();
    UserDetails loadUserByUsername(String usernameOrEmail);
}
