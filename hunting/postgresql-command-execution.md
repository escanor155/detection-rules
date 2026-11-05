# PostgreSQL: detecting operating-system command execution

`COPY ... TO PROGRAM` and `pg_read_file()` are documented features. They need a
superuser (or a role with `pg_execute_server_program` / `pg_read_server_files`),
which is exactly why an application account holding those rights is worth
finding before an attacker does.

This is a hunting note rather than a Sigma rule: the event lives in the database
statement log or in `pg_stat_activity`, not in process creation telemetry. If
you do collect process creation, `rules/linux_postgres_spawns_shell.yml` catches
the resulting shell.

## Live sessions

```sql
SELECT pid,
       usename,
       client_addr,
       state,
       query_start,
       query
FROM pg_stat_activity
WHERE query ~* '(copy\s+.+\s+(to|from)\s+program'
   OR query ~* '(pg_read_file|pg_read_binary_file|pg_ls_dir|lo_import|lo_export)';
```

Run it on a schedule and alert on any row. Normal application queries do not
mention these functions.

## Statement log

With `log_statement = 'all'`, the server writes the text of every statement:

```
2026-11-05 08:41:12 UTC LOG:  statement: COPY (SELECT '') TO PROGRAM 'id'
2026-11-05 08:41:19 UTC LOG:  statement: SELECT pg_read_file('/var/www/html/config.php')
```

`log_statement = 'all'` is loud; enable it for a session while hunting, or keep
`log_min_duration_statement = 0` plus `log_statement = 'ddl'` in production and
accept that data-manipulation statements will be missing.

## Who can do it

```sql
-- superusers
SELECT rolname FROM pg_roles WHERE rolsuper;

-- non-superusers granted the predefined file/program roles (PostgreSQL 11+)
SELECT member.rolname AS login_role, granted.rolname AS granted_role
FROM pg_auth_members am
JOIN pg_roles member  ON member.oid  = am.member
JOIN pg_roles granted ON granted.oid = am.roleid
WHERE granted.rolname IN (
        'pg_execute_server_program',
        'pg_read_server_files',
        'pg_write_server_files'
      );
```

Simpler and sufficient in most cases: check `pg_roles.rolsuper` and confirm the
application does not connect as a superuser. In the lab box the web application
connected as `postgres`; that single design decision turned a SQL injection into
remote code execution.

## Blind spots

- Statements executed through a pooler may be logged with the pooler's user and
  client address, not the real one.
- `COPY ... FROM PROGRAM` runs on the server and looks identical in the log to
  `TO PROGRAM`. Alert on both.
- Nothing here fires if the attacker uses an extension such as `plpython3u`
  instead of `COPY`. Process creation for the postgres account covers that case.
