-- Returns only a closed proof marker, never a database role or tenant identity.
-- The runtime connection and its login must not reach privileged/owner roles.
SELECT CASE WHEN
    EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = current_user
    )
    AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = session_user
    )
    AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS authority
        WHERE (authority.rolsuper OR authority.rolbypassrls)
          AND (
              pg_catalog.pg_has_role(current_user, authority.oid, 'MEMBER')
              OR pg_catalog.pg_has_role(session_user, authority.oid, 'MEMBER')
          )
    )
    AND pg_catalog.current_setting('row_security') = 'on'
    AND (
        SELECT count(*)
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relname IN ('workspaces', 'principals', 'memberships')
          AND relation.relkind IN ('r', 'p')
    ) = 3
    AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND (
              relation.relname IN ('principals', 'workspaces', 'memory_share_proposals')
              OR EXISTS (
                  SELECT 1 FROM pg_catalog.pg_attribute AS attribute
                  WHERE attribute.attrelid = relation.oid
                    AND attribute.attname = 'workspace_id'
                    AND attribute.attnum > 0
                    AND NOT attribute.attisdropped
              )
          )
          AND (
              relation.relkind NOT IN ('r', 'p')
              OR NOT relation.relrowsecurity
              OR NOT relation.relforcerowsecurity
              OR pg_catalog.pg_has_role(current_user, relation.relowner, 'MEMBER')
              OR pg_catalog.pg_has_role(session_user, relation.relowner, 'MEMBER')
              OR pg_catalog.to_regclass(pg_catalog.quote_ident(relation.relname))
                    IS DISTINCT FROM relation.oid
          )
    )
THEN 'restricted-runtime'::text ELSE NULL::text END;
