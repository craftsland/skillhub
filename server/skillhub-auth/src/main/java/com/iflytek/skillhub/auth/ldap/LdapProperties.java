package com.iflytek.skillhub.auth.ldap;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Static configuration for the built-in LDAP/Active Directory provider.
 */
@Component
@ConfigurationProperties(prefix = "skillhub.auth.ldap")
public class LdapProperties {

    private boolean enabled;
    private String providerCode = "ldap";
    private String displayName = "Corporate Directory";
    private String authority;
    private String url;
    private boolean startTls;
    private boolean allowInsecureForTesting;
    private String directoryType = "OPENLDAP";
    private String baseDn;
    private String userSearchBase = "";
    private String userSearchFilter = "(uid={0})";
    private String bindDn;
    private String bindPassword;
    private String subjectAttribute;
    private String subjectType;
    private String usernameAttribute = "uid";
    private String displayNameAttribute = "displayName";
    private String emailAttribute = "mail";
    private String avatarUrlAttribute;
    private boolean emailAuthoritative;
    private Duration connectTimeout = Duration.ofSeconds(5);
    private Duration readTimeout = Duration.ofSeconds(10);
    private Duration poolWaitTimeout = Duration.ofSeconds(2);
    private int maxConcurrentRequests = 16;
    private int maxAttributeValues = 16;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getProviderCode() {
        return providerCode;
    }

    public void setProviderCode(String providerCode) {
        this.providerCode = providerCode;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isStartTls() {
        return startTls;
    }

    public void setStartTls(boolean startTls) {
        this.startTls = startTls;
    }

    public boolean isAllowInsecureForTesting() {
        return allowInsecureForTesting;
    }

    public void setAllowInsecureForTesting(boolean allowInsecureForTesting) {
        this.allowInsecureForTesting = allowInsecureForTesting;
    }

    public String getDirectoryType() {
        return directoryType;
    }

    public void setDirectoryType(String directoryType) {
        this.directoryType = directoryType;
    }

    public String getBaseDn() {
        return baseDn;
    }

    public void setBaseDn(String baseDn) {
        this.baseDn = baseDn;
    }

    public String getUserSearchBase() {
        return userSearchBase;
    }

    public void setUserSearchBase(String userSearchBase) {
        this.userSearchBase = userSearchBase;
    }

    public String getUserSearchFilter() {
        return userSearchFilter;
    }

    public void setUserSearchFilter(String userSearchFilter) {
        this.userSearchFilter = userSearchFilter;
    }

    public String getBindDn() {
        return bindDn;
    }

    public void setBindDn(String bindDn) {
        this.bindDn = bindDn;
    }

    public String getBindPassword() {
        return bindPassword;
    }

    public void setBindPassword(String bindPassword) {
        this.bindPassword = bindPassword;
    }

    public String getSubjectAttribute() {
        return subjectAttribute;
    }

    public void setSubjectAttribute(String subjectAttribute) {
        this.subjectAttribute = subjectAttribute;
    }

    public String getSubjectType() {
        return subjectType;
    }

    public void setSubjectType(String subjectType) {
        this.subjectType = subjectType;
    }

    public String getUsernameAttribute() {
        return usernameAttribute;
    }

    public void setUsernameAttribute(String usernameAttribute) {
        this.usernameAttribute = usernameAttribute;
    }

    public String getDisplayNameAttribute() {
        return displayNameAttribute;
    }

    public void setDisplayNameAttribute(String displayNameAttribute) {
        this.displayNameAttribute = displayNameAttribute;
    }

    public String getEmailAttribute() {
        return emailAttribute;
    }

    public void setEmailAttribute(String emailAttribute) {
        this.emailAttribute = emailAttribute;
    }

    public String getAvatarUrlAttribute() {
        return avatarUrlAttribute;
    }

    public void setAvatarUrlAttribute(String avatarUrlAttribute) {
        this.avatarUrlAttribute = avatarUrlAttribute;
    }

    public boolean isEmailAuthoritative() {
        return emailAuthoritative;
    }

    public void setEmailAuthoritative(boolean emailAuthoritative) {
        this.emailAuthoritative = emailAuthoritative;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(Duration connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public Duration getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(Duration readTimeout) {
        this.readTimeout = readTimeout;
    }

    public Duration getPoolWaitTimeout() {
        return poolWaitTimeout;
    }

    public void setPoolWaitTimeout(Duration poolWaitTimeout) {
        this.poolWaitTimeout = poolWaitTimeout;
    }

    public int getMaxConcurrentRequests() {
        return maxConcurrentRequests;
    }

    public void setMaxConcurrentRequests(int maxConcurrentRequests) {
        this.maxConcurrentRequests = maxConcurrentRequests;
    }

    public int getMaxAttributeValues() {
        return maxAttributeValues;
    }

    public void setMaxAttributeValues(int maxAttributeValues) {
        this.maxAttributeValues = maxAttributeValues;
    }
}
