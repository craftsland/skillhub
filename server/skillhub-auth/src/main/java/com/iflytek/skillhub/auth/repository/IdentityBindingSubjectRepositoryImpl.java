package com.iflytek.skillhub.auth.repository;

import com.iflytek.skillhub.auth.entity.IdentityBindingSubject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

class IdentityBindingSubjectRepositoryImpl
        implements IdentityBindingSubjectLookupRepository {

    private final EntityManager entityManager;

    IdentityBindingSubjectRepositoryImpl(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public List<IdentityBindingSubject> findMatchingSubjects(
            String providerCode,
            Map<String, Set<String>> subjectValuesByType) {
        if (subjectValuesByType.isEmpty()) {
            return List.of();
        }

        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<IdentityBindingSubject> query =
                builder.createQuery(IdentityBindingSubject.class);
        Root<IdentityBindingSubject> subject =
                query.from(IdentityBindingSubject.class);

        List<Predicate> exactPairs = new ArrayList<>();
        subjectValuesByType.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> entry.getValue().stream()
                        .sorted(Comparator.naturalOrder())
                        .forEach(value -> exactPairs.add(builder.and(
                                builder.equal(
                                        subject.get("subjectType"),
                                        entry.getKey()),
                                builder.equal(
                                        subject.get("subjectValue"),
                                        value)))));

        query.select(subject)
                .where(builder.and(
                        builder.equal(
                                subject.get("providerCode"),
                                providerCode),
                        builder.or(exactPairs.toArray(Predicate[]::new))))
                .orderBy(builder.asc(subject.get("id")));
        return entityManager.createQuery(query).getResultList();
    }
}
