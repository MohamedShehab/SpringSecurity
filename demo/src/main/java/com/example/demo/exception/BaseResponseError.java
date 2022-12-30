package com.example.demo.exception;

import org.springframework.http.HttpStatus;

public class BaseResponseError{

    private String message;
    private int errorCode = HttpStatus.INTERNAL_SERVER_ERROR.value();



    public BaseResponseError(String message, int errorCode) {
        this.message = message;
        this.errorCode = errorCode;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }
}
