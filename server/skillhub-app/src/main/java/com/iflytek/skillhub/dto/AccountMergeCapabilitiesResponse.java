package com.iflytek.skillhub.dto;

import java.util.List;

/**
 * Login methods that can independently prove the primary and secondary
 * accounts without identifying a secondary account in advance.
 */
public record AccountMergeCapabilitiesResponse(
        boolean enabled,
        List<AccountMergeAuthenticationMethodResponse> primaryMethods,
        List<AccountMergeAuthenticationMethodResponse> secondaryMethods
) {
    public AccountMergeCapabilitiesResponse {
        primaryMethods = List.copyOf(primaryMethods);
        secondaryMethods = List.copyOf(secondaryMethods);
    }
}
