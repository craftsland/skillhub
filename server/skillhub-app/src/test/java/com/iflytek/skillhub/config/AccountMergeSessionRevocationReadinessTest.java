package com.iflytek.skillhub.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.iflytek.skillhub.auth.merge.AccountMergeProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.session.FindByIndexNameSessionRepository;

class AccountMergeSessionRevocationReadinessTest {

    private static final String ENABLED =
            "skillhub.auth.account-merge.enabled=true";

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner()
                    .withUserConfiguration(
                            AccountMergeSessionRevocationReadiness.class);

    @Test
    void enablingAccountMergeWithoutIndexedSessionsFailsStartup() {
        contextRunner
                .withPropertyValues(ENABLED)
                .withBean(
                        AccountMergeProperties.class,
                        () -> properties(true))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasMessageContaining(
                                    "FindByIndexNameSessionRepository");
                });
    }

    @Test
    void disabledAccountMergeDoesNotRequireIndexedSessions() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(
                    AccountMergeSessionRevocationReadiness.class);
        });
    }

    @Test
    @SuppressWarnings({"rawtypes", "unchecked"})
    void enablingAccountMergeWithIndexedSessionsIsReady() {
        contextRunner
                .withPropertyValues(
                        ENABLED)
                .withBean(
                        AccountMergeProperties.class,
                        () -> properties(true))
                .withBean(
                        FindByIndexNameSessionRepository.class,
                        () -> mock(
                                FindByIndexNameSessionRepository.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(
                            AccountMergeSessionRevocationReadiness.class);
                });
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    void enablingAccountMergeBeforeSessionCutoverFailsStartup() {
        contextRunner
                .withPropertyValues(ENABLED)
                .withBean(
                        AccountMergeProperties.class,
                        () -> properties(false))
                .withBean(
                        FindByIndexNameSessionRepository.class,
                        () -> mock(
                                FindByIndexNameSessionRepository.class))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .hasMessageContaining(
                                    "namespace cutover");
                });
    }

    private static AccountMergeProperties properties(
            boolean sessionCutoverComplete) {
        AccountMergeProperties properties =
                new AccountMergeProperties();
        properties.setEnabled(true);
        properties.setSessionCutoverComplete(
                sessionCutoverComplete);
        return properties;
    }
}
