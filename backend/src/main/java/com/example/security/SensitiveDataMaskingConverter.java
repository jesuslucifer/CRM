package com.example.security;

import ch.qos.logback.classic.pattern.MessageConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class SensitiveDataMaskingConverter extends MessageConverter {

    private static final Pattern JWT_PATTERN = Pattern.compile(
            "([A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.)?[A-Za-z0-9-_.=]+"
    );

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "(?i)(password\"?\\s*[:=]\\s*\"?)([^\",\\s}]+\"?)"
    );

    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            "(accessToken|token|refreshToken\"?\\s*[:=]\\s*\"?)([A-Za-z0-9-_.=]+)"
    );

    @Override
    public String convert(ILoggingEvent event) {
        String message = event.getFormattedMessage();

        message = PASSWORD_PATTERN.matcher(message).replaceAll("$1***");

        message = TOKEN_PATTERN.matcher(message).replaceAll(match -> {
            String prefix = match.group(1);
            String token = match.group(2);
            if (token.length() > 20) {
                String masked = token.substring(0, 10) + "..." + token.substring(token.length() - 10);
                return prefix + masked;
            }
            return prefix + "***";
        });

        return message;
    }
}
