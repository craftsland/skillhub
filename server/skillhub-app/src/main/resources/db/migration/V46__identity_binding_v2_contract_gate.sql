-- Binding V2 contract gate.
--
-- Deploy this migration only after every pre-Binding-V2 application instance
-- has exited. Unlike the V45 expand migration, this gate rejects transactions
-- that leave an ACTIVE binding without exactly one ACTIVE primary subject.

DO $$
DECLARE
    violation_summary TEXT;
BEGIN
    SELECT string_agg(
        format(
            '%s (%s active primary subjects)',
            binding_id,
            active_primary_count
        ),
        ', ' ORDER BY binding_id
    )
    INTO violation_summary
    FROM (
        SELECT
            binding.id AS binding_id,
            COUNT(subject.id) FILTER (
                WHERE subject.status = 'ACTIVE'
                  AND subject.is_primary = TRUE
            ) AS active_primary_count
        FROM identity_binding binding
        LEFT JOIN identity_binding_subject subject
          ON subject.binding_id = binding.id
        WHERE binding.status = 'ACTIVE'
        GROUP BY binding.id
        HAVING COUNT(subject.id) FILTER (
            WHERE subject.status = 'ACTIVE'
              AND subject.is_primary = TRUE
        ) <> 1
        ORDER BY binding.id
        LIMIT 20
    ) violations;

    IF violation_summary IS NOT NULL THEN
        RAISE EXCEPTION
            'Binding V2 contract preflight failed: ACTIVE bindings must have exactly one ACTIVE primary subject: %',
            violation_summary;
    END IF;
END
$$;

CREATE FUNCTION assert_identity_binding_active_primary(
    target_binding_id BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    binding_active BOOLEAN;
    active_primary_count BIGINT;
BEGIN
    SELECT
        binding.status = 'ACTIVE',
        COUNT(subject.id) FILTER (
            WHERE subject.status = 'ACTIVE'
              AND subject.is_primary = TRUE
        )
    INTO binding_active, active_primary_count
    FROM identity_binding binding
    LEFT JOIN identity_binding_subject subject
      ON subject.binding_id = binding.id
    WHERE binding.id = target_binding_id
    GROUP BY binding.status;

    IF NOT FOUND OR NOT binding_active THEN
        RETURN;
    END IF;

    IF active_primary_count <> 1 THEN
        RAISE EXCEPTION
            'ACTIVE identity binding % must have exactly one ACTIVE primary subject; found %',
            target_binding_id,
            active_primary_count
            USING
                ERRCODE = '23514',
                CONSTRAINT = 'chk_identity_binding_active_primary';
    END IF;
END
$$;

CREATE FUNCTION enforce_identity_binding_subject_primary()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM assert_identity_binding_active_primary(NEW.binding_id);
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM assert_identity_binding_active_primary(OLD.binding_id);
    ELSE
        PERFORM assert_identity_binding_active_primary(OLD.binding_id);
        IF NEW.binding_id IS DISTINCT FROM OLD.binding_id THEN
            PERFORM assert_identity_binding_active_primary(NEW.binding_id);
        END IF;
    END IF;
    RETURN NULL;
END
$$;

CREATE FUNCTION enforce_identity_binding_primary()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM assert_identity_binding_active_primary(NEW.id);
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER ct_identity_binding_subject_active_primary
AFTER INSERT OR UPDATE OR DELETE
ON identity_binding_subject
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION enforce_identity_binding_subject_primary();

CREATE CONSTRAINT TRIGGER ct_identity_binding_active_primary
AFTER INSERT OR UPDATE
ON identity_binding
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION enforce_identity_binding_primary();
