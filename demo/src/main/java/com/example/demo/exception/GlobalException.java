package com.example.demo.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalException {

    @ExceptionHandler(MissingServletRequestParameterException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public BaseResponseError handleMissingParam(MissingServletRequestParameterException ex){
        return new BaseResponseError(ex.getMessage() , HttpStatus.BAD_REQUEST.value());
    }

    @ExceptionHandler(MissingPathVariableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public BaseResponseError handleMissingPathVariable(MissingPathVariableException ex){
        return new BaseResponseError(ex.getMessage() , HttpStatus.BAD_REQUEST.value());
    }
}
