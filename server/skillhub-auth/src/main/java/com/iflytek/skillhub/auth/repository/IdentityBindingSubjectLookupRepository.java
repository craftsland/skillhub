package com.iflytek.skillhub.auth.repository;

import com.iflytek.skillhub.auth.entity.IdentityBindingSubject;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Exact typed-subject lookup. Subject type and value remain paired so the
 * query cannot accidentally match the Cartesian product of independent IN
 * clauses.
 */
public interface IdentityBindingSubjectLookupRepository {

    List<IdentityBindingSubject> findMatchingSubjects(
            String providerCode,
            Map<String, Set<String>> subjectValuesByType);
}
