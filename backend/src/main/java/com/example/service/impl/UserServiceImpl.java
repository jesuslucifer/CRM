package com.example.service.impl;

import com.example.exception.*;
import com.example.model.User;
import com.example.model.dto.request.update.UserUpdateRequest;
import com.example.model.dto.response.DealDto;
import com.example.model.dto.response.OrderDto;
import com.example.model.dto.response.UserDto;
import com.example.repository.UserRepository;
import com.example.service.LocalStorageService;
import com.example.service.UserService;
import com.example.specification.UserSpecification;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserDetailsService, UserService {
    private final UserRepository userRepository;
    private final LocalStorageService localStorageService;
    private final PasswordEncoder passwordEncoder;

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
    public User getByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(EmailNotFoundException::new);
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
        String fileUrl = localStorageService.uploadAvatar(file, filename);

        user.setAvatarUrl(fileUrl);
        userRepository.save(user);
    }

    @Override
    public UserDetailsService userDetailsService() {
        return this::getByUsername;
    }

    @Override
    public User update(Long id, UserUpdateRequest userDto) {
        User user = getById(id);

        if (userDto.getName() != null) {
            user.setName(userDto.getName());
        }

        if (userDto.getLastName() != null) {
            user.setLastName(userDto.getLastName());
        }

        if (userDto.getUsername() != null) {
            if (userRepository.existsByUsername(userDto.getUsername())) {
                throw new UsernameAlreadyExistsException();
            }
            user.setUsername(userDto.getUsername());
        }

        return userRepository.save(user);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public User changePassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        return userRepository.save(user);
    }

    @Override
    public User changeEmail(Long id, String newEmail, String password) {
        User user = getById(id);

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new WrongPasswordException();
        }

        if (userRepository.existsByEmail(newEmail)) {
            throw new EmailAlreadyExistsException();
        }

        user.setEmail(newEmail);

        return userRepository.save(user);
    }

    @Override
    public User changePasswordWithConfirmPassword(User user, String newPassword, String confirmPassword) {
        if (passwordEncoder.matches(newPassword, user.getPassword())) {
            log.info("perv");
            throw new WrongPasswordException();
        }

        if (!passwordEncoder.matches(confirmPassword, user.getPassword())) {
            log.info("vtor");
            throw new WrongPasswordException();
        }

        user.setPassword(passwordEncoder.encode(newPassword));

        return userRepository.save(user);
    }

    @Override
    public List<OrderDto> getOrders(User user) {
        return user.getOrders()
                .stream()
                .map(OrderDto::new)
                .toList();
    }

    @Override
    public List<DealDto> getDeals(User user) {
        return user.getDeals()
                .stream()
                .map((DealDto::new))
                .toList();
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
