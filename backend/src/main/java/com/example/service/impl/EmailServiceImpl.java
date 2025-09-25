package com.example.service.impl;

import com.example.model.User;
import com.example.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {
    private final JavaMailSender mailSender;
    @Value("${spring.mail.username}")
    private String from;

    @Override
    public void send(String to, String subject, String body) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setFrom(from);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(body, true);

            mailSender.send(message);
            log.info("[EMAIL] : Уведомление отправлено пользователю {} : {}", to, body);

        } catch (MessagingException e) {
            log.error("[EMAIL] : Ошибка при отправке уведомления пользователю {}", to, e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void sendPasswordResetToken(String email, String contextPath, User user, String token) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            String resetUrl = contextPath + "/reset-password?token=" + token;

            helper.setFrom(from);
            helper.setTo(user.getEmail());
            helper.setSubject("Восстановление пароля");
            helper.setText(createPasswordResetEmailHtml(resetUrl), true);

            mailSender.send(message);
            log.info("[EMAIL] : Уведомление отправлено пользователю {} : {}", user.getEmail(), "Восстановление пароля");

        } catch (MessagingException e) {
            log.error("[EMAIL] : Ошибка при отправке уведомления пользователю {}", user.getEmail(), e);
            throw new RuntimeException(e);
        }
    }

    private String createPasswordResetEmailHtml(String resetUrl) {
        return """
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Восстановление пароля</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                    }
                    .container {
                        background-color: #f9f9f9;
                        border-radius: 10px;
                        padding: 30px;
                        margin: 20px 0;
                    }
                    .header {
                        text-align: center;
                        margin-bottom: 30px;
                    }
                    .button {
                        display: inline-block;
                        background-color: #007bff;
                        color: white;
                        padding: 12px 30px;
                        text-decoration: none;
                        border-radius: 5px;
                        margin: 20px 0;
                        font-size: 16px;
                    }
                    .button:hover {
                        background-color: #0056b3;
                    }
                    .footer {
                        margin-top: 30px;
                        font-size: 12px;
                        color: #666;
                        text-align: center;
                    }
                    .token {
                        background-color: #f0f0f0;
                        padding: 10px;
                        border-radius: 5px;
                        word-break: break-all;
                        margin: 15px 0;
                        font-family: monospace;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>Восстановление пароля</h2>
                    </div>
                    
                    <p>Здравствуйте!</p>
                    
                    <p>Мы получили запрос на восстановление пароля для вашей учетной записи.</p>
                    
                    <p>Для установки нового пароля нажмите на кнопку ниже:</p>
                    
                    <div style="text-align: center;">
                        <a href="%s" class="button">Восстановить пароль</a>
                    </div>
                    
                    <p>Если кнопка не работает, скопируйте и вставьте следующую ссылку в браузер:</p>
                    
                    <div class="token">%s</div>
                    
                    <p><strong>Ссылка действительна в течение 24 часов.</strong></p>
                    
                    <p>Если вы не запрашивали восстановление пароля, просто проигнорируйте это письмо.</p>
                    
                    <div class="footer">
                        <p>С уважением,<br>Команда поддержки</p>
                        <p>Если у вас возникли вопросы, свяжитесь с нами: support@example.com</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(resetUrl, resetUrl);
    }
}
