package com.iflytek.skillhub.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.auth.entity.Role;
import com.iflytek.skillhub.auth.entity.UserRoleBinding;
import com.iflytek.skillhub.auth.repository.RoleRepository;
import com.iflytek.skillhub.auth.repository.UserRoleBindingRepository;
import com.iflytek.skillhub.domain.namespace.GlobalNamespaceMembershipService;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.domain.shared.exception.DomainBadRequestException;
import com.iflytek.skillhub.domain.shared.exception.DomainForbiddenException;
import com.iflytek.skillhub.domain.shared.exception.DomainNotFoundException;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import com.iflytek.skillhub.domain.user.UserStatus;
import com.iflytek.skillhub.dto.AdminUserMutationResponse;
import com.iflytek.skillhub.dto.AdminUserSummaryResponse;
import com.iflytek.skillhub.dto.PageResponse;
import com.iflytek.skillhub.repository.AdminUserSearchRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.slf4j.MDC;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Administrative user-management application service built around the main
 * search and mutation use cases exposed by the admin API.
 */
@Service
public class AdminUserAppService {

    private static final Set<UserStatus> MANAGEABLE_STATUSES = Set.of(UserStatus.ACTIVE, UserStatus.DISABLED);
    private static final String SUPER_ADMIN_ROLE = "SUPER_ADMIN";
    private static final String USER_ROLE = "USER";

    private final AdminUserSearchRepository adminUserSearchRepository;
    private final UserAccountRepository userAccountRepository;
    private final UserRoleBindingRepository userRoleBindingRepository;
    private final RoleRepository roleRepository;
    private final GlobalNamespaceMembershipService globalNamespaceMembershipService;
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;

    public AdminUserAppService(
            AdminUserSearchRepository adminUserSearchRepository,
            UserAccountRepository userAccountRepository,
            UserRoleBindingRepository userRoleBindingRepository,
            RoleRepository roleRepository,
            GlobalNamespaceMembershipService globalNamespaceMembershipService,
            AuditLogService auditLogService,
            ObjectMapper objectMapper) {
        this.adminUserSearchRepository = adminUserSearchRepository;
        this.userAccountRepository = userAccountRepository;
        this.userRoleBindingRepository = userRoleBindingRepository;
        this.roleRepository = roleRepository;
        this.globalNamespaceMembershipService = globalNamespaceMembershipService;
        this.auditLogService = auditLogService;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public PageResponse<AdminUserSummaryResponse> listUsers(String search, String status, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<UserAccount> result = adminUserSearchRepository.search(
                search,
                StringUtils.hasText(status) ? parseStatus(status) : null,
                pageable
        );
        Map<String, List<String>> rolesByUserId = loadRolesByUserId(
                result.getContent().stream().map(UserAccount::getId).toList());

        List<AdminUserSummaryResponse> items = result.getContent().stream()
                .map(user -> new AdminUserSummaryResponse(
                        user.getId(),
                        user.getDisplayName(),
                        user.getEmail(),
                        user.getStatus().name(),
                        rolesByUserId.getOrDefault(user.getId(), List.of()),
                        user.getCreatedAt()))
                .toList();

        return new PageResponse<>(items, result.getTotalElements(), result.getNumber(), result.getSize());
    }

    @Transactional
    public AdminUserMutationResponse updateUserRole(String userId, String roleCode, Set<String> actorPlatformRoles) {
        UserAccount user = loadUser(userId);
        rejectSystemAccountMutation(user);
        String normalizedRoleCode = normalizeRoleCode(roleCode);
        boolean targetHasSuperAdminRole = userRoleBindingRepository.findByUserId(user.getId()).stream()
                .anyMatch(binding -> SUPER_ADMIN_ROLE.equals(binding.getRole().getCode()));

        if ((SUPER_ADMIN_ROLE.equals(normalizedRoleCode) || targetHasSuperAdminRole)
                && (actorPlatformRoles == null || !actorPlatformRoles.contains(SUPER_ADMIN_ROLE))) {
            throw new DomainForbiddenException("error.admin.user.role.superAdmin.assignDenied");
        }

        userRoleBindingRepository.deleteByUserId(user.getId());

        if (!USER_ROLE.equals(normalizedRoleCode)) {
            Role role = roleRepository.findByCode(normalizedRoleCode)
                    .orElseThrow(() -> new DomainBadRequestException("error.admin.user.role.invalid", roleCode));
            userRoleBindingRepository.save(new UserRoleBinding(user.getId(), role));
        }

        return new AdminUserMutationResponse(user.getId(), normalizedRoleCode, user.getStatus().name());
    }

    @Transactional
    public AdminUserMutationResponse updateUserStatus(String userId, String status) {
        return updateUserStatus(
                userId,
                status,
                null,
                null);
    }

    @Transactional
    public AdminUserMutationResponse updateUserStatus(
            String userId,
            String status,
            String actorUserId,
            AuditRequestContext auditContext) {
        UserAccount user = loadUserForUpdate(userId);
        rejectSystemAccountMutation(user);
        UserStatus nextStatus = parseManageableStatus(status);
        UserStatus previousStatus = user.getStatus();
        if (nextStatus == UserStatus.ACTIVE && user.getStatus() == UserStatus.MERGED) {
            throw new DomainBadRequestException("error.admin.user.status.mergedCannotActivate");
        }
        user.setStatus(nextStatus);
        userAccountRepository.save(user);
        if (nextStatus == UserStatus.ACTIVE) {
            globalNamespaceMembershipService.ensureMember(user.getId());
        }
        if (actorUserId != null) {
            auditLogService.record(
                    actorUserId,
                    statusAuditAction(
                            previousStatus,
                            nextStatus),
                    "USER_ACCOUNT",
                    null,
                    MDC.get("requestId"),
                    auditContext != null
                            ? auditContext.clientIp()
                            : null,
                    auditContext != null
                            ? auditContext.userAgent()
                            : null,
                    statusAuditDetail(
                            userId,
                            previousStatus,
                            nextStatus));
        }
        return new AdminUserMutationResponse(user.getId(), null, nextStatus.name());
    }

    private String statusAuditAction(
            UserStatus previousStatus,
            UserStatus nextStatus) {
        if (previousStatus == UserStatus.PENDING
                && nextStatus == UserStatus.ACTIVE) {
            return "IDENTITY_PROVISIONING_APPROVED";
        }
        if (previousStatus == UserStatus.PENDING
                && nextStatus == UserStatus.DISABLED) {
            return "IDENTITY_PROVISIONING_REJECTED";
        }
        return "USER_STATUS_UPDATED";
    }

    private String statusAuditDetail(
            String userId,
            UserStatus previousStatus,
            UserStatus nextStatus) {
        try {
            return objectMapper.writeValueAsString(Map.of(
                    "userId",
                    userId,
                    "previousStatus",
                    previousStatus.name(),
                    "status",
                    nextStatus.name()));
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException(
                    "Failed to serialize user status audit",
                    exception);
        }
    }

    private UserStatus parseManageableStatus(String status) {
        UserStatus parsedStatus = parseStatus(status);
        if (!MANAGEABLE_STATUSES.contains(parsedStatus)) {
            throw new DomainBadRequestException("error.admin.user.status.unsupported");
        }
        return parsedStatus;
    }

    private UserStatus parseStatus(String status) {
        try {
            return UserStatus.valueOf(status.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new DomainBadRequestException("error.admin.user.status.invalid", status);
        }
    }

    private String normalizeRoleCode(String roleCode) {
        if (!StringUtils.hasText(roleCode)) {
            throw new DomainBadRequestException("error.admin.user.role.invalid", roleCode);
        }
        return roleCode.trim().toUpperCase(Locale.ROOT);
    }

    private Map<String, List<String>> loadRolesByUserId(List<String> userIds) {
        if (userIds.isEmpty()) {
            return Map.of();
        }
        Map<String, List<String>> explicitRolesByUserId = userRoleBindingRepository.findByUserIdIn(userIds).stream()
                .collect(Collectors.groupingBy(
                        UserRoleBinding::getUserId,
                        Collectors.mapping(binding -> binding.getRole().getCode(),
                                Collectors.collectingAndThen(Collectors.toList(),
                                        roles -> roles.stream().sorted().toList()))));
        return userIds.stream().collect(Collectors.toMap(
                userId -> userId,
                userId -> withDefaultUserRole(explicitRolesByUserId.getOrDefault(userId, List.of())).stream()
                        .sorted()
                        .toList()
        ));
    }

    private Set<String> withDefaultUserRole(List<String> roles) {
        Set<String> resolvedRoles = new TreeSet<>();
        if (roles != null) {
            resolvedRoles.addAll(roles);
        }
        if (resolvedRoles.isEmpty()) {
            resolvedRoles.add("USER");
        }
        return Set.copyOf(resolvedRoles);
    }

    private UserAccount loadUser(String userId) {
        return userAccountRepository.findById(userId)
                .orElseThrow(() -> new DomainNotFoundException("error.admin.user.notFound", userId));
    }

    private UserAccount loadUserForUpdate(String userId) {
        return userAccountRepository.findByIdForUpdate(userId)
                .orElseThrow(() -> new DomainNotFoundException(
                        "error.admin.user.notFound",
                        userId));
    }

    private void rejectSystemAccountMutation(UserAccount user) {
        if (user.isSystemAccount()) {
            throw new DomainForbiddenException("error.admin.user.systemAccount.immutable");
        }
    }
}
