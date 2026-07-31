package com.iflytek.skillhub.controller;

import com.iflytek.skillhub.dto.IdentityLinkErrorResponse;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@ApiResponses({
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "200",
                description = "Operation completed"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "400",
                description = "Invalid identity link operation",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        IdentityLinkErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "401",
                description = "Fresh reauthentication required",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        IdentityLinkErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "403",
                description = "Intent belongs to another session",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        IdentityLinkErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "404",
                description = "Identity Link intent was not found",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        IdentityLinkErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "409",
                description = "Identity conflict, consumed intent, or final login method",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        IdentityLinkErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "410",
                description = "Intent expired",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        IdentityLinkErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "503",
                description = "Identity provider unavailable",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        IdentityLinkErrorResponse.class)))
})
public @interface IdentityLinkMutationResponses {
}
