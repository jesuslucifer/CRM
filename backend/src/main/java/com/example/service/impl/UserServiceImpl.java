package com.example.service.impl;

import com.example.exception.*;
import com.example.model.User;
import com.example.model.dto.response.UserDto;
import com.example.repository.UserRepository;
import com.example.service.LocalStorageService;
import com.example.service.UserService;
import com.example.specification.UserSpecification;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserDetailsService, UserService {
    private final UserRepository userRepository;
    private final LocalStorageService localStorageService;

    @Override
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    public User create(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new UsernameAlreadyExistsException();
        }

        if (userRepository.existsByEmail(user.getEmail())) {
            throw new EmailAlreadyExistsException();
        }

        return save(user);
    }

    @Override
    public User getByUsernameOrEmail(String usernameOrEmail) {
        if (usernameOrEmail.contains("@")) {
            return userRepository.findByEmail(usernameOrEmail)
                    .orElseThrow(AuthenticationFailedException::new);
        } else {
            return userRepository.findByUsername(usernameOrEmail)
                    .orElseThrow(AuthenticationFailedException::new);
        }
    }

    @Override
    public User getByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(UsernameNotFoundException::new);
    }

    @Override
    public User getById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(IdNotFoundException::new);
    }

    @Override
    public List<UserDto> getAll(String username, Pageable pageable) {
        Specification<User> spec = Specification.where(UserSpecification.byUsernameLike(username));

        return userRepository.findAll(spec, pageable)
                .stream().map(UserDto::new)
                .collect(Collectors.toList());
    }

    @Override
    public void updateAvatarUrl(Long id, MultipartFile file) {
        User user = userRepository.findById(id)
                .orElseThrow(IdNotFoundException::new);

        if (file.isEmpty()) {
            throw new UploadFileIsEmptyException();
        }

        if (!file.getContentType().startsWith("image")) {
            throw new InvalidFileTypeException();
        }

        String filename = "avatar_user_" + user.getId() + "_" + System.currentTimeMillis();
        String fileUrl = localStorageService.uploadFile(file, filename);

        user.setAvatarUrl(fileUrl);
        userRepository.save(user);

    }

    @Override
    public UserDetailsService userDetailsService() {
        return this::getByUsername;
    }

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        if (usernameOrEmail.contains("@")) {
            return userRepository.findByEmail(usernameOrEmail)
                    .orElseThrow(EmailNotFoundException::new);
        } else {
            return userRepository.findByUsername(usernameOrEmail)
                    .orElseThrow(UsernameNotFoundException::new);
        }
    }
}
