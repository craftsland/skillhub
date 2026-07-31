package com.iflytek.skillhub.auth.merge;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.util.Objects;

/**
 * Server-side result of a successful primary provider reauthentication.
 */
public record AccountMergeProviderPrimaryProof(
        PlatformPrincipal principal,
        AccountMergePrimaryProof proof
) {
    public AccountMergeProviderPrimaryProof {
        Objects.requireNonNull(principal, "principal");
        Objects.requireNonNull(proof, "proof");
    }
}
