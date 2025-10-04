package com.example.controller;

import com.example.model.PasswordResetToken;
import com.example.model.User;
import com.example.model.dto.request.EmailPasswordUsernameRequest;
import com.example.model.dto.request.PasswordRequest;
import com.example.model.dto.response.ErrorResponse;
import com.example.model.dto.response.SuccessResponse;
import com.example.model.dto.response.UserDto;
import com.example.security.SecurityUtil;
import com.example.service.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final PasswordResetTokenService passwordResetTokenService;
    private final EmailService emailService;
    private final TokenService tokenService;
    private final JwtService jwtService;

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        User user = SecurityUtil.getCurrentUser();

        return ResponseEntity.ok(new UserDto(user));
    }

    @PostMapping("/avatar")
    public ResponseEntity<?> updateAvatarUrl(@RequestParam("file") MultipartFile avatarUrlRequest) {
        userService.updateAvatarUrl(SecurityUtil.getCurrentUser().getId(), avatarUrlRequest);

        return ResponseEntity.ok(new SuccessResponse(
                "Аватар обновлен",
                HttpStatus.OK
        ));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getUser(@PathVariable Long id) {
        User user = userService.getById(id);

        return ResponseEntity.ok(new UserDto(user));
    }

    @GetMapping
    public ResponseEntity<?> getUsers(
            @RequestParam (required = false) String username,
            Pageable pageable) {

        return ResponseEntity.ok(userService.getAll(username, pageable));
    }

    @PutMapping("/{id}/name")
    public ResponseEntity<UserDto> updateNameAndLastName(
            @PathVariable Long id,
            @RequestBody UserDto userDto) {

        userService.updateNameAndLastName(id, userDto);

        return ResponseEntity.ok(new UserDto(userService.getById(id)));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody EmailPasswordUsernameRequest email, HttpServletRequest request) {
        try {
            Optional<User> userOptional = userService.findByEmail(email.getEmail());

            if (userOptional.isPresent()) {
                User user = userOptional.get();

                passwordResetTokenService.deletePasswordResetTokenByUser(user);

                PasswordResetToken passwordResetToken = passwordResetTokenService.create(user);

                emailService.sendPasswordResetToken(email.getEmail(), getAppUrl(request), user, passwordResetToken.getToken());
            }

            return ResponseEntity.ok(new SuccessResponse(
                    "Инструкция к восстановлению пароля отправлена на ваш email",
                    HttpStatus.OK
            ));
        } catch (Exception e) {
            return ResponseEntity.ok(new ErrorResponse(
                    "Error",
                    HttpStatus.BAD_REQUEST
            ));
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(HttpServletRequest request) {
        try {
            User user = userService.getById(SecurityUtil.getCurrentUser().getId());

            passwordResetTokenService.deletePasswordResetTokenByUser(user);

            PasswordResetToken passwordResetToken = passwordResetTokenService.create(user);

            emailService.sendPasswordResetToken(user.getEmail(), getAppUrl(request), user, passwordResetToken.getToken());

            return ResponseEntity.ok(new SuccessResponse(
                    "Инструкция по смене пароля отправлена на ваш email",
                    HttpStatus.OK
            ));
        } catch (Exception e) {
            return ResponseEntity.ok(new ErrorResponse(
                    "Error",
                    HttpStatus.BAD_REQUEST
            ));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestBody PasswordRequest password) {
        try {
            PasswordResetToken passwordResetToken = passwordResetTokenService.getPasswordResetToken(token);

            if (passwordResetToken.isExpired()) {
                return ResponseEntity.ok(new ErrorResponse(
                        "Токен истек",
                        HttpStatus.BAD_REQUEST
                ));
            }
            User user = passwordResetToken.getUser();

            userService.changePassword(user, password.getPassword());

            passwordResetTokenService.deletePasswordResetToken(token);

            tokenService.removeToken(user);

            return ResponseEntity.ok(new SuccessResponse(
                    "Пароль изменен",
                    HttpStatus.OK
            ));
        } catch (Exception e) {
            return ResponseEntity.ok(new ErrorResponse(
                    "Error",
                    HttpStatus.BAD_REQUEST
            ));
        }
    }

    @PostMapping("/change-email")
    public ResponseEntity<?> changeEmail(@RequestBody EmailPasswordUsernameRequest request) {
        User user = userService.changeEmail(
                SecurityUtil.getCurrentUser().getId(),
                request.getEmail(),
                request.getPassword());

        return ResponseEntity.ok(new UserDto(user));
    }

    private String getAppUrl(HttpServletRequest request) {
        return request.getScheme() +
                "://" +
                request.getServerName() +
                ":" +
                request.getServerPort() +
                request.getContextPath();
    }
}
