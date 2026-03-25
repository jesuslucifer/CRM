package com.example.service;

import com.example.model.User;
import com.example.model.dto.request.UserUpdateRequest;
import com.example.model.dto.response.UserDto;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

public interface UserService {
    User save(User user);
    User create(User user);
    User getByUsernameOrEmail(String usernameOrEmail);
    User getByUsername(String username);
    User getById(Long id);
    List<UserDto> getAll(String username, Pageable pageable);
    void updateAvatarUrl(Long id, MultipartFile file);
    UserDetails loadUserByUsername(String usernameOrEmail);
    UserDetailsService userDetailsService();
    User update(Long id, UserUpdateRequest userDto);
    Optional<User> findByEmail(String email);
    User changePassword(User user, String newPassword);
    User changeEmail(Long id, String newEmail, String password);
    User changePasswordWithConfirmPassword(User user, String newPassword, String confirmPassword);
}
