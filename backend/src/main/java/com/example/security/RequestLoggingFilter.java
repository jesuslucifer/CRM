package com.example.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class RequestLoggingFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request);

        filterChain.doFilter(wrappedRequest, response);

        // Логируем только если произошла ошибка
        if (response.getStatus() >= 400) {
            byte[] body = wrappedRequest.getContentAsByteArray();
            String requestBody = new String(body, StandardCharsets.UTF_8);

            System.err.println("=== ERROR REQUEST ===");
            System.err.println("Status: " + response.getStatus());
            System.err.println("Method: " + request.getMethod());
            System.err.println("URL: " + request.getRequestURL());
            System.err.println("Body: " + requestBody);
            System.err.println("====================");
        }
    }
}
