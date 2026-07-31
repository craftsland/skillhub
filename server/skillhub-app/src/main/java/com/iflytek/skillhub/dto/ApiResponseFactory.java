package com.iflytek.skillhub.dto;

import com.iflytek.skillhub.observability.RequestIdAccessor;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Component;
import org.springframework.context.i18n.LocaleContextHolder;

import java.time.Clock;
import java.time.Instant;

@Component
public class ApiResponseFactory {

    private final MessageSource messageSource;
    private final Clock clock;
    private final RequestIdAccessor requestIdAccessor;

    public ApiResponseFactory(MessageSource messageSource,
                              Clock clock,
                              RequestIdAccessor requestIdAccessor) {
        this.messageSource = messageSource;
        this.clock = clock;
        this.requestIdAccessor = requestIdAccessor;
    }

    public <T> ApiResponse<T> ok(String messageCode, T data, Object... args) {
        String msg = messageSource.getMessage(messageCode, args, messageCode, LocaleContextHolder.getLocale());
        return new ApiResponse<>(0, msg, data, Instant.now(clock), requestIdAccessor.current());
    }

    public ApiResponse<Void> error(int code, String messageCode, Object... args) {
        String msg = messageSource.getMessage(messageCode, args, messageCode, LocaleContextHolder.getLocale());
        return new ApiResponse<>(code, msg, null, Instant.now(clock), requestIdAccessor.current());
    }

    public ApiResponse<Void> errorMessage(int code, String msg) {
        return new ApiResponse<>(code, msg, null, Instant.now(clock), requestIdAccessor.current());
    }

    public IdentityLinkErrorResponse identityLinkError(
            int code,
            String messageCode,
            String reasonCode,
            Object... args) {
        String msg = messageSource.getMessage(
                messageCode,
                args,
                messageCode,
                LocaleContextHolder.getLocale());
        return new IdentityLinkErrorResponse(
                code,
                msg,
                reasonCode,
                Instant.now(clock),
                requestIdAccessor.current());
    }

    public IdentityLinkErrorResponse identityLinkErrorMessage(
            int code,
            String message,
            String reasonCode) {
        return new IdentityLinkErrorResponse(
                code,
                message,
                reasonCode,
                Instant.now(clock),
                requestIdAccessor.current());
    }
}
