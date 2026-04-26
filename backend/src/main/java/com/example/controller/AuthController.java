package com.example.controller;

import com.example.exception.AuthenticationFailedException;
import com.example.model.dto.request.RefreshTokenRequest;
import com.example.model.dto.request.SignInRequest;
import com.example.model.dto.request.SignUpRequest;
import com.example.model.dto.response.JwtResponse;
import com.example.model.enums.Role;
import com.example.model.User;
import com.example.model.dto.response.SuccessResponse;
import com.example.service.JwtService;
import com.example.service.TokenService;
import com.example.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody SignInRequest signInRequest) {
        try {
            User user = userService.getByUsernameOrEmail(signInRequest.getUsernameOrEmail());

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), signInRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtService.generateAccessToken(user);

            String refreshToken = jwtService.generateRefreshToken(user);

            tokenService.saveToken(refreshToken, user);

            return ResponseEntity.ok(new JwtResponse(accessToken, refreshToken));
        } catch (Exception e) {
            throw new AuthenticationFailedException();
        }
    }

    @PostMapping("/sign-up")
    public SuccessResponse registerCompany(@RequestBody SignUpRequest signUpRequest) {
        var user = User.builder()
                .username(signUpRequest.getUsername())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .role(Role.USER)
                .avatarUrl("http://localhost:8080/uploads/avatars/default.jpg")
                .build();

        userService.create(user);

        return new SuccessResponse(
                "Успешна регистрация",
                HttpStatus.OK);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        String requestRefreshTokenRefreshToken = request.getRefreshToken();

        String username = jwtService.extractUsername(requestRefreshTokenRefreshToken);

        User user = userService.getByUsername(username);

        if (!jwtService.validateRefreshToken(requestRefreshTokenRefreshToken, user)) {
            return ResponseEntity.badRequest().body("Invalid refresh token");
        }

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        tokenService.removeToken(user);

        tokenService.saveToken(refreshToken, user);

        return ResponseEntity.ok(new JwtResponse(accessToken, refreshToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        User user = (User) authentication.getPrincipal();

        tokenService.removeToken(user);

        return ResponseEntity.ok(new SuccessResponse(
                "Успешный выход",
                HttpStatus.OK
        ));
    }
}
