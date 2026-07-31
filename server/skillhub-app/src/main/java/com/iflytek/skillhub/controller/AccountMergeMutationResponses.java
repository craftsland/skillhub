package com.iflytek.skillhub.controller;

import com.iflytek.skillhub.dto.AccountMergeErrorResponse;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Stable error contract shared by the safe account-merge resources.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@ApiResponses({
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "200",
                description = "Operation completed"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "400",
                description = "Invalid account merge request",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        AccountMergeErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "401",
                description = "Fresh authentication failed or is required",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        AccountMergeErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "403",
                description = "Intent belongs to another browser session",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        AccountMergeErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "404",
                description = "Account merge intent was not found",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        AccountMergeErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "409",
                description = "Conflict, stale preview, or consumed intent",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        AccountMergeErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "410",
                description = "Account merge proof or intent expired",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        AccountMergeErrorResponse.class))),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(
                responseCode = "503",
                description = "Account merge or provider unavailable",
                content = @Content(
                        schema = @Schema(
                                implementation =
                                        AccountMergeErrorResponse.class)))
})
public @interface AccountMergeMutationResponses {
}
