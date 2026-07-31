package com.iflytek.skillhub.auth.cas;

/**
 * CAS service-ticket validation endpoint and preferred response format.
 */
public enum CasProtocolVersion {
    V2_0("2.0", "/serviceValidate", false),
    V3_0("3.0", "/p3/serviceValidate", true);

    private final String wireValue;
    private final String validationPath;
    private final boolean jsonPreferred;

    CasProtocolVersion(
            String wireValue,
            String validationPath,
            boolean jsonPreferred) {
        this.wireValue = wireValue;
        this.validationPath = validationPath;
        this.jsonPreferred = jsonPreferred;
    }

    public String wireValue() {
        return wireValue;
    }

    String validationPath() {
        return validationPath;
    }

    boolean jsonPreferred() {
        return jsonPreferred;
    }

    static CasProtocolVersion parse(String value) {
        return switch (value) {
            case "2.0" -> V2_0;
            case "3.0" -> V3_0;
            default -> throw new IllegalArgumentException(
                    "Unsupported CAS protocol version");
        };
    }
}
