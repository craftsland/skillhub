package com.iflytek.skillhub.controller;

import com.iflytek.skillhub.service.CasLoginAppService;
import com.iflytek.skillhub.service.CasLoginFailure;
import com.iflytek.skillhub.service.CasLoginFlowException;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * CAS browser transport. Protocol verification and identity resolution are
 * delegated to application and auth services.
 */
@Controller
@RequestMapping("/api/v1/auth/cas/{providerCode}")
public class CasLoginController {

    private static final Logger log = LoggerFactory.getLogger(
            CasLoginController.class);

    private final CasLoginAppService loginAppService;

    public CasLoginController(
            CasLoginAppService loginAppService) {
        this.loginAppService = loginAppService;
    }

    @GetMapping("/login")
    public ResponseEntity<Void> login(
            @PathVariable String providerCode,
            @RequestParam(required = false) String returnTo,
            HttpServletRequest request) {
        try {
            return redirect(loginAppService.begin(
                    providerCode,
                    returnTo,
                    request));
        } catch (CasLoginFlowException exception) {
            return redirect(failureTarget(exception.failure()));
        } catch (RuntimeException exception) {
            logUnexpected(providerCode, exception);
            return redirect(failureTarget(
                    CasLoginFailure.INTERNAL_ERROR));
        }
    }

    @GetMapping("/callback")
    public ResponseEntity<Void> callback(
            @PathVariable String providerCode,
            @RequestParam(required = false) String ticket,
            @RequestParam(required = false) String state,
            HttpServletRequest request) {
        try {
            return redirect(URI.create(loginAppService.complete(
                    providerCode,
                    ticket,
                    state,
                    request)));
        } catch (CasLoginFlowException exception) {
            return redirect(failureTarget(exception.failure()));
        } catch (RuntimeException exception) {
            logUnexpected(providerCode, exception);
            return redirect(failureTarget(
                    CasLoginFailure.INTERNAL_ERROR));
        }
    }

    private ResponseEntity<Void> redirect(URI target) {
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(target)
                .build();
    }

    private URI failureTarget(CasLoginFailure failure) {
        return switch (failure) {
            case ACCOUNT_PENDING -> URI.create("/pending-approval");
            case ACCESS_DENIED -> URI.create("/access-denied");
            case LINK_REQUIRED ->
                    URI.create("/login?reason=linkRequired");
            case INVALID_STATE ->
                    URI.create("/login?reason=casInvalidState");
            case TICKET_MISSING ->
                    URI.create("/login?reason=casTicketMissing");
            case VALIDATION_FAILED ->
                    URI.create("/login?reason=casValidationFailed");
            case PROVIDER_UNAVAILABLE ->
                    URI.create("/login?reason=casUnavailable");
            case INTERNAL_ERROR ->
                    URI.create("/login?reason=internalError");
        };
    }

    private void logUnexpected(
            String providerCode,
            RuntimeException exception) {
        log.error(
                "CAS browser flow failed unexpectedly [requestId={}, provider={}, failure={}]",
                MDC.get("requestId"),
                providerCode,
                exception.getClass().getSimpleName());
    }
}
