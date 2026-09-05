-- Versioned browser state; only the application worker has access. Tokens are
-- AEAD ciphertext, cookie/state keys are SHA-256 digests, never bearer values.
-- Apply atomically under the browser-schema advisory lock, at READ COMMITTED.
-- An existing namespace is validation-only: no DDL, marker insert, or repair.
DO $$
DECLARE
    marker regclass := pg_catalog.to_regclass('apex_browser_session_schema');
    sessions regclass := pg_catalog.to_regclass('apex_browser_sessions');
    attempts regclass := pg_catalog.to_regclass('apex_browser_login_attempts');
    admission regclass := pg_catalog.to_regclass('apex_browser_login_admission');
    relation_name text;
    relation_id oid;
    expected record;
    actual_checks text[];
    expected_checks text[];
    count_all bigint;
    count_supported bigint;
BEGIN
    IF marker IS NULL AND sessions IS NULL AND attempts IS NULL AND admission IS NULL THEN
        IF pg_catalog.current_setting('apex.browser_session_create',true)='off' THEN
            RAISE EXCEPTION 'missing browser session storage on reconnect' USING ERRCODE='0A000';
        END IF;
        CREATE TABLE apex_browser_login_attempts (
            state_digest bytea PRIMARY KEY CHECK(octet_length(state_digest)=32),
            browser_digest bytea NOT NULL CHECK(octet_length(browser_digest)=32),
            issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
            client_id text NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 256),
            created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp()))::bigint,
            expires_at bigint NOT NULL,
            token_version integer NOT NULL CHECK(token_version=1),
            token_key_id text NOT NULL CHECK(token_key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
            token_nonce bytea NOT NULL CHECK(octet_length(token_nonce)=24),
            token_ciphertext bytea NOT NULL CHECK(octet_length(token_ciphertext) BETWEEN 16 AND 65552),
            CHECK(expires_at>created_at AND expires_at-created_at<=600)
        );
        CREATE INDEX apex_browser_login_expiry_idx ON apex_browser_login_attempts(expires_at);

        CREATE TABLE apex_browser_sessions (
            session_digest bytea PRIMARY KEY CHECK(octet_length(session_digest)=32),
            issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
            client_id text NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 256),
            subject text NOT NULL CHECK(octet_length(subject) BETWEEN 1 AND 512),
            csrf_binding bytea NOT NULL CHECK(octet_length(csrf_binding)=32),
            created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp()))::bigint,
            absolute_expires_at bigint NOT NULL,
            idle_expires_at bigint NOT NULL CHECK(idle_expires_at>0 AND idle_expires_at<=absolute_expires_at),
            access_expires_at bigint NOT NULL CHECK(access_expires_at>0),
            refresh_expires_at bigint NOT NULL CHECK(refresh_expires_at>0),
            generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),
            state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','refreshing','revoked')),
            refresh_deadline bigint,
            token_version integer CHECK(token_version=1),
            token_key_id text CHECK(token_key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
            token_nonce bytea CHECK(octet_length(token_nonce)=24),
            token_ciphertext bytea CHECK(octet_length(token_ciphertext) BETWEEN 16 AND 65552),
            CHECK(absolute_expires_at>created_at AND absolute_expires_at-created_at<=86400),
            CHECK((state='refreshing' AND refresh_deadline IS NOT NULL AND generation>0)
                OR (state<>'refreshing' AND refresh_deadline IS NULL)),
            CHECK((state='revoked' AND token_version IS NULL AND token_key_id IS NULL
                AND token_nonce IS NULL AND token_ciphertext IS NULL)
                OR (state<>'revoked' AND token_version IS NOT NULL AND token_key_id IS NOT NULL
                AND token_nonce IS NOT NULL AND token_ciphertext IS NOT NULL))
        );
        CREATE INDEX apex_browser_session_idle_idx ON apex_browser_sessions(idle_expires_at);
        CREATE INDEX apex_browser_session_absolute_idx ON apex_browser_sessions(absolute_expires_at);
        CREATE INDEX apex_browser_session_refresh_idx ON apex_browser_sessions(refresh_deadline)
            WHERE state='refreshing';

        -- Format 2 adds one permanent deployment-global admission bucket.
        -- This row is never recreated, pruned or reset by an existing-store path.
        CREATE TABLE apex_browser_login_admission (
            singleton smallint PRIMARY KEY CHECK(singleton=1),
            tat_us bigint NOT NULL CHECK(tat_us>=0),
            clock_us bigint NOT NULL CHECK(clock_us>=0)
        );
        INSERT INTO apex_browser_login_admission VALUES(1,0,0);
        CREATE TABLE apex_browser_session_schema(version integer PRIMARY KEY CHECK(version=2));
        INSERT INTO apex_browser_session_schema(version) VALUES(2);
    ELSIF marker IS NULL OR sessions IS NULL OR attempts IS NULL OR admission IS NULL THEN
        RAISE EXCEPTION 'unversioned or incomplete browser session storage' USING ERRCODE='0A000';
    END IF;

    -- Fresh models and existing version markers use exactly the same validator.
    -- Lock all four relations through commit so concurrent DDL or marker writes
    -- cannot change the evidence while it is being checked. No provider I/O here.
    FOREACH relation_name IN ARRAY ARRAY[
        'apex_browser_session_schema','apex_browser_login_attempts','apex_browser_sessions',
        'apex_browser_login_admission'
    ] LOOP
        relation_id := pg_catalog.to_regclass(relation_name);
        EXECUTE format('LOCK TABLE %s IN SHARE MODE', relation_id::regclass);
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE c.oid=relation_id AND n.nspname=current_schema()
              AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relispartition
              AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
        ) THEN
            RAISE EXCEPTION 'incompatible browser session relation' USING ERRCODE='0A000';
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=relation_id OR inhparent=relation_id)
           OR EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation_id AND NOT tgisinternal)
           OR EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=relation_id) THEN
            RAISE EXCEPTION 'incompatible browser session relation behavior' USING ERRCODE='0A000';
        END IF;
    END LOOP;

    -- Exact live column shape, including absence of unspecified defaults.
    -- pg_get_expr preserves expression grouping; do not strip parentheses or
    -- compare substrings of checks/defaults (that could accept weaker logic).
    FOR expected IN
        SELECT * FROM (VALUES
            ('apex_browser_session_schema','version','integer',true,NULL::text),
            ('apex_browser_login_admission','singleton','smallint',true,NULL),
            ('apex_browser_login_admission','tat_us','bigint',true,NULL),
            ('apex_browser_login_admission','clock_us','bigint',true,NULL),
            ('apex_browser_login_attempts','state_digest','bytea',true,NULL),
            ('apex_browser_login_attempts','browser_digest','bytea',true,NULL),
            ('apex_browser_login_attempts','issuer','text',true,NULL),
            ('apex_browser_login_attempts','client_id','text',true,NULL),
            ('apex_browser_login_attempts','created_at','bigint',true,'(floor(EXTRACT(epoch FROM clock_timestamp())))::bigint'),
            ('apex_browser_login_attempts','expires_at','bigint',true,NULL),
            ('apex_browser_login_attempts','token_version','integer',true,NULL),
            ('apex_browser_login_attempts','token_key_id','text',true,NULL),
            ('apex_browser_login_attempts','token_nonce','bytea',true,NULL),
            ('apex_browser_login_attempts','token_ciphertext','bytea',true,NULL),
            ('apex_browser_sessions','session_digest','bytea',true,NULL),
            ('apex_browser_sessions','issuer','text',true,NULL),
            ('apex_browser_sessions','client_id','text',true,NULL),
            ('apex_browser_sessions','subject','text',true,NULL),
            ('apex_browser_sessions','csrf_binding','bytea',true,NULL),
            ('apex_browser_sessions','created_at','bigint',true,'(floor(EXTRACT(epoch FROM clock_timestamp())))::bigint'),
            ('apex_browser_sessions','absolute_expires_at','bigint',true,NULL),
            ('apex_browser_sessions','idle_expires_at','bigint',true,NULL),
            ('apex_browser_sessions','access_expires_at','bigint',true,NULL),
            ('apex_browser_sessions','refresh_expires_at','bigint',true,NULL),
            ('apex_browser_sessions','generation','bigint',true,'0'),
            ('apex_browser_sessions','state','text',true,'''active''::text'),
            ('apex_browser_sessions','refresh_deadline','bigint',false,NULL),
            ('apex_browser_sessions','token_version','integer',false,NULL),
            ('apex_browser_sessions','token_key_id','text',false,NULL),
            ('apex_browser_sessions','token_nonce','bytea',false,NULL),
            ('apex_browser_sessions','token_ciphertext','bytea',false,NULL)
        ) AS model(table_name,column_name,type_name,not_null,default_expr)
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_attribute a
            LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
            WHERE a.attrelid=pg_catalog.to_regclass(expected.table_name)
              AND a.attname=expected.column_name AND a.attnum>0 AND NOT a.attisdropped
              AND a.atttypid=expected.type_name::regtype AND a.atttypmod=-1
              AND a.attnotnull=expected.not_null AND a.attidentity='' AND a.attgenerated=''
              AND a.attcollation=(SELECT typcollation FROM pg_catalog.pg_type WHERE oid=a.atttypid)
              AND pg_catalog.pg_get_expr(d.adbin,d.adrelid) IS NOT DISTINCT FROM expected.default_expr
        ) THEN
            RAISE EXCEPTION 'incompatible browser session column: %.%', expected.table_name,expected.column_name
                USING ERRCODE='0A000';
        END IF;
    END LOOP;

    FOR expected IN
        SELECT * FROM (VALUES
            ('apex_browser_session_schema','version',1),
            ('apex_browser_login_admission','singleton',3),
            ('apex_browser_login_attempts','state_digest',10),
            ('apex_browser_sessions','session_digest',17)
        ) AS model(table_name,key_name,column_count)
    LOOP
        relation_id := pg_catalog.to_regclass(expected.table_name);
        IF (SELECT count(*) FROM pg_catalog.pg_attribute
            WHERE attrelid=relation_id AND attnum>0 AND NOT attisdropped)<>expected.column_count
           OR (SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid=relation_id AND contype='p')<>1
           OR NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint k
            JOIN pg_catalog.pg_attribute a ON a.attrelid=k.conrelid AND a.attname=expected.key_name
            JOIN pg_catalog.pg_index i ON i.indexrelid=k.conindid AND i.indrelid=k.conrelid
            WHERE k.conrelid=relation_id AND k.contype='p' AND k.conkey=ARRAY[a.attnum]
              AND k.convalidated AND NOT k.condeferrable AND NOT k.condeferred
              AND i.indisprimary AND i.indisunique AND i.indisvalid AND i.indisready
              AND i.indislive AND i.indimmediate AND i.indnkeyatts=1 AND i.indnatts=1
              AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indkey[0]=a.attnum
        ) THEN
            RAISE EXCEPTION 'incompatible browser session primary key or column count' USING ERRCODE='0A000';
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=relation_id
              AND (NOT convalidated OR condeferrable OR condeferred OR contype NOT IN ('p','c','n'))
        ) THEN
            RAISE EXCEPTION 'incompatible browser session constraint status' USING ERRCODE='0A000';
        END IF;

        -- Compare complete deparsed check expressions, independent of constraint
        -- names. NOT VALID checks are refused above even if their text matches.
        SELECT array_agg(pg_catalog.pg_get_expr(conbin,conrelid) ORDER BY pg_catalog.pg_get_expr(conbin,conrelid))
            INTO actual_checks FROM pg_catalog.pg_constraint WHERE conrelid=relation_id AND contype='c';
        IF expected.table_name='apex_browser_session_schema' THEN
            expected_checks := ARRAY['(version = 2)'];
        ELSIF expected.table_name='apex_browser_login_admission' THEN
            expected_checks := ARRAY['(singleton = 1)','(tat_us >= 0)','(clock_us >= 0)'];
        ELSIF expected.table_name='apex_browser_login_attempts' THEN
            expected_checks := ARRAY[
                '(octet_length(state_digest) = 32)',
                '(octet_length(browser_digest) = 32)',
                '((octet_length(issuer) >= 1) AND (octet_length(issuer) <= 2048))',
                '((octet_length(client_id) >= 1) AND (octet_length(client_id) <= 256))',
                '(token_version = 1)',
                '(token_key_id ~ ''^[A-Za-z0-9._-]{1,64}$''::text)',
                '(octet_length(token_nonce) = 24)',
                '((octet_length(token_ciphertext) >= 16) AND (octet_length(token_ciphertext) <= 65552))',
                '((expires_at > created_at) AND ((expires_at - created_at) <= 600))'
            ];
        ELSE
            expected_checks := ARRAY[
                '(octet_length(session_digest) = 32)',
                '((octet_length(issuer) >= 1) AND (octet_length(issuer) <= 2048))',
                '((octet_length(client_id) >= 1) AND (octet_length(client_id) <= 256))',
                '((octet_length(subject) >= 1) AND (octet_length(subject) <= 512))',
                '(octet_length(csrf_binding) = 32)',
                '((idle_expires_at > 0) AND (idle_expires_at <= absolute_expires_at))',
                '(access_expires_at > 0)',
                '(refresh_expires_at > 0)',
                '(generation >= 0)',
                '(state = ANY (ARRAY[''active''::text, ''refreshing''::text, ''revoked''::text]))',
                '(token_version = 1)',
                '(token_key_id ~ ''^[A-Za-z0-9._-]{1,64}$''::text)',
                '(octet_length(token_nonce) = 24)',
                '((octet_length(token_ciphertext) >= 16) AND (octet_length(token_ciphertext) <= 65552))',
                '((absolute_expires_at > created_at) AND ((absolute_expires_at - created_at) <= 86400))',
                '(((state = ''refreshing''::text) AND (refresh_deadline IS NOT NULL) AND (generation > 0)) OR ((state <> ''refreshing''::text) AND (refresh_deadline IS NULL)))',
                '(((state = ''revoked''::text) AND (token_version IS NULL) AND (token_key_id IS NULL) AND (token_nonce IS NULL) AND (token_ciphertext IS NULL)) OR ((state <> ''revoked''::text) AND (token_version IS NOT NULL) AND (token_key_id IS NOT NULL) AND (token_nonce IS NOT NULL) AND (token_ciphertext IS NOT NULL)))'
            ];
        END IF;
        SELECT array_agg(expr ORDER BY expr) INTO expected_checks FROM unnest(expected_checks) AS checks(expr);
        IF actual_checks IS DISTINCT FROM expected_checks THEN
            RAISE EXCEPTION 'incompatible browser session checks: %',expected.table_name USING ERRCODE='0A000';
        END IF;
    END LOOP;

    SELECT count(*),count(*) FILTER (WHERE version=2)
        INTO count_all,count_supported FROM apex_browser_session_schema;
    IF count_all<>1 OR count_supported<>1 THEN
        RAISE EXCEPTION 'incompatible browser session version' USING ERRCODE='0A000';
    END IF;
    SELECT count(*),count(*) FILTER (WHERE singleton=1)
        INTO count_all,count_supported FROM apex_browser_login_admission;
    IF count_all<>1 OR count_supported<>1 THEN
        RAISE EXCEPTION 'missing or incompatible browser admission singleton' USING ERRCODE='0A000';
    END IF;
END;
$$;
