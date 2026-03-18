package com.example.exception;

import com.example.model.dto.response.ErrorResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        System.err.println("Validation errors: " + errors);

        return ResponseEntity.badRequest().body(errors);
    }

    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationFailed() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Ошибка авторизации",
                HttpStatus.UNAUTHORIZED
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(UsernameAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleUsernameAlreadyExists() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Имя пользователя уже занято",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleEmailAlreadyExists() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Электронная почта уже занята",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUsernameNotFound() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Имя пользователя не найдено",
                HttpStatus.NOT_FOUND
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(EmailNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleEmailNotFound() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Электронная почта не найдена",
                HttpStatus.NOT_FOUND
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(IdNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleIdNotFound() {
        ErrorResponse errorResponse = new ErrorResponse(
                "ID не найден",
                HttpStatus.NOT_FOUND
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(UploadFileException.class)
    public ResponseEntity<ErrorResponse> handleUploadFile() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Ошибка загрузки файла",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(InvalidFileTypeException.class)
    public ResponseEntity<ErrorResponse> handleInvalidFileType() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Недопустимый тип файла",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(UploadFileIsEmptyException.class)
    public ResponseEntity<ErrorResponse> handleUploadFileIsEmpty() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Файл пуст",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFound() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Пользователь не найден",
                HttpStatus.NOT_FOUND
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(CompanyNameAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleCompanyNameAlreadyExists() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Компания с таким именем уже существует",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(CompanyNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleCompanyNotFound() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Компания не найдена",
                HttpStatus.NOT_FOUND
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(EmployeeAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleEmployeeAlreadyExistsInCompany() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Сотрудник уже находится в компании",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(EmployeeNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleEmployeeNotFoundInCompany() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Сотрудника нет в компании",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(WrongPasswordException.class)
    public ResponseEntity<ErrorResponse> handleWrongPassword() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Неверный пароль",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(ClientAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleClientAlreadyExists() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Клиент с такими данными уже существует",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(ClientNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleClientNotFound() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Клиент не найден",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(PhoneAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handlePhoneAlreadyExists() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Телефон уже занят",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(PropertyAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handlePropertyAlreadyExists() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Недвижимость уже существует",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(PropertyNotFoundException.class)
    public ResponseEntity<ErrorResponse> handlePropertyNotFound() {
        ErrorResponse errorResponse = new ErrorResponse(
                "Недвижимость не найдена",
                HttpStatus.BAD_REQUEST
        );
        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }
}
