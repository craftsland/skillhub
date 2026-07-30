package com.iflytek.skillhub.auth.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

final class ProviderAuthorityFingerprint {

    private ProviderAuthorityFingerprint() {
    }

    static String sha256(String protocol, String canonicalAuthority) {
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(canonicalAuthority, "canonicalAuthority");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] input = (protocol + "\n" + canonicalAuthority)
                    .getBytes(StandardCharsets.UTF_8);
            return HexFormat.of().formatHex(digest.digest(input));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
