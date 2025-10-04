package com.example.exception;

public class WrongPasswordException extends RuntimeException {
    public WrongPasswordException() {
        super("Неверный пароль");
    }
}
