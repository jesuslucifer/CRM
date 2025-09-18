package com.example.controller;

import com.example.model.User;
import com.example.model.dto.response.SuccessResponse;
import com.example.model.dto.response.UserDto;
import com.example.security.SecurityUtil;
import com.example.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

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
}
