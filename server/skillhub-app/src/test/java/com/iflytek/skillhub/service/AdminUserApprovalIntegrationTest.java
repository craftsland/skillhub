package com.iflytek.skillhub.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doAnswer;

import com.iflytek.skillhub.SkillhubApplication;
import com.iflytek.skillhub.TestRedisConfig;
import com.iflytek.skillhub.domain.namespace.GlobalNamespaceMembershipService;
import com.iflytek.skillhub.domain.namespace.Namespace;
import com.iflytek.skillhub.domain.namespace.NamespaceRole;
import com.iflytek.skillhub.domain.namespace.NamespaceType;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserStatus;
import com.iflytek.skillhub.infra.jpa.NamespaceJpaRepository;
import com.iflytek.skillhub.infra.jpa.NamespaceMemberJpaRepository;
import com.iflytek.skillhub.infra.jpa.UserAccountJpaRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest(classes = SkillhubApplication.class)
@ActiveProfiles("test")
@Import(TestRedisConfig.class)
class AdminUserApprovalIntegrationTest {

    @Autowired
    private AdminUserAppService adminUserAppService;

    @Autowired
    private UserAccountJpaRepository userAccountRepository;

    @Autowired
    private NamespaceJpaRepository namespaceRepository;

    @Autowired
    private NamespaceMemberJpaRepository namespaceMemberRepository;

    @Autowired
    private TransactionTemplate transactionTemplate;

    @SpyBean
    private GlobalNamespaceMembershipService globalNamespaceMembershipService;

    private String userId;

    @BeforeEach
    void setUp() {
        userId = "pending-" + UUID.randomUUID();
        transactionTemplate.executeWithoutResult(status -> {
            ensureGlobalNamespace();
            UserAccount user = new UserAccount(userId, "Pending User", null, null);
            user.setStatus(UserStatus.PENDING);
            userAccountRepository.saveAndFlush(user);
        });
    }

    @AfterEach
    void tearDown() {
        transactionTemplate.executeWithoutResult(status -> {
            namespaceMemberRepository.findByUserId(userId)
                    .forEach(namespaceMemberRepository::delete);
            userAccountRepository.deleteById(userId);
        });
    }

    @Test
    void activatingPendingUser_createsGlobalMembershipInSameWorkflow() {
        adminUserAppService.updateUserStatus(userId, "ACTIVE");

        transactionTemplate.executeWithoutResult(status -> {
            UserAccount approved = userAccountRepository.findAllById(List.of(userId))
                    .stream()
                    .findFirst()
                    .orElseThrow();
            Namespace global = namespaceRepository.findBySlug("global").orElseThrow();

            assertThat(approved.getStatus()).isEqualTo(UserStatus.ACTIVE);
            assertThat(namespaceMemberRepository.findByNamespaceIdAndUserId(global.getId(), userId))
                    .get()
                    .extracting(member -> member.getRole())
                    .isEqualTo(NamespaceRole.MEMBER);
        });
    }

    @Test
    void approvingActiveUserAgain_keepsSingleGlobalMembership() {
        adminUserAppService.updateUserStatus(userId, "ACTIVE");
        adminUserAppService.updateUserStatus(userId, "ACTIVE");

        transactionTemplate.executeWithoutResult(status -> {
            Namespace global = namespaceRepository.findBySlug("global").orElseThrow();
            assertThat(namespaceMemberRepository.findByUserId(userId))
                    .filteredOn(member -> member.getNamespaceId().equals(global.getId()))
                    .singleElement()
                    .extracting(member -> member.getRole())
                    .isEqualTo(NamespaceRole.MEMBER);
        });
    }

    @Test
    void enablingDisabledUser_createsGlobalMembership() {
        setUserStatus(UserStatus.DISABLED);

        adminUserAppService.updateUserStatus(userId, "ACTIVE");

        transactionTemplate.executeWithoutResult(status -> {
            UserAccount enabled = userAccountRepository.findAllById(List.of(userId))
                    .stream()
                    .findFirst()
                    .orElseThrow();
            Namespace global = namespaceRepository.findBySlug("global").orElseThrow();

            assertThat(enabled.getStatus()).isEqualTo(UserStatus.ACTIVE);
            assertThat(namespaceMemberRepository.findByNamespaceIdAndUserId(global.getId(), userId))
                    .get()
                    .extracting(member -> member.getRole())
                    .isEqualTo(NamespaceRole.MEMBER);
        });
    }

    @Test
    void membershipFailure_rollsBackPendingUserActivation() {
        doAnswer(invocation -> {
            userAccountRepository.flush();
            throw new IllegalStateException("membership write failed");
        }).when(globalNamespaceMembershipService).ensureMember(userId);

        assertThatThrownBy(() -> adminUserAppService.updateUserStatus(userId, "ACTIVE"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("membership write failed");

        transactionTemplate.executeWithoutResult(status -> {
            UserAccount user = userAccountRepository.findAllById(List.of(userId))
                    .stream()
                    .findFirst()
                    .orElseThrow();
            Namespace global = namespaceRepository.findBySlug("global").orElseThrow();

            assertThat(user.getStatus()).isEqualTo(UserStatus.PENDING);
            assertThat(namespaceMemberRepository.findByNamespaceIdAndUserId(global.getId(), userId))
                    .isEmpty();
        });
    }

    @Test
    void membershipFailure_rollsBackDisabledUserActivation() {
        setUserStatus(UserStatus.DISABLED);
        doAnswer(invocation -> {
            userAccountRepository.flush();
            throw new IllegalStateException("membership write failed");
        }).when(globalNamespaceMembershipService).ensureMember(userId);

        assertThatThrownBy(() -> adminUserAppService.updateUserStatus(userId, "ACTIVE"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("membership write failed");

        transactionTemplate.executeWithoutResult(status -> {
            UserAccount user = userAccountRepository.findAllById(List.of(userId))
                    .stream()
                    .findFirst()
                    .orElseThrow();
            Namespace global = namespaceRepository.findBySlug("global").orElseThrow();

            assertThat(user.getStatus()).isEqualTo(UserStatus.DISABLED);
            assertThat(namespaceMemberRepository.findByNamespaceIdAndUserId(global.getId(), userId))
                    .isEmpty();
        });
    }

    private void setUserStatus(UserStatus status) {
        transactionTemplate.executeWithoutResult(transactionStatus -> {
            UserAccount user = userAccountRepository.findAllById(List.of(userId))
                    .stream()
                    .findFirst()
                    .orElseThrow();
            user.setStatus(status);
            userAccountRepository.saveAndFlush(user);
        });
    }

    private void ensureGlobalNamespace() {
        if (namespaceRepository.findBySlug("global").isPresent()) {
            return;
        }
        Namespace global = new Namespace("global", "Global", null);
        global.setType(NamespaceType.GLOBAL);
        namespaceRepository.saveAndFlush(global);
    }
}
