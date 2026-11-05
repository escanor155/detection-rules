# Anonymous FTP: detecting logins and what they took

Anonymous FTP is not automatically a problem; anonymous FTP that exposes the web
root, a backup or a home directory is. There is no single portable log format,
so this is a hunting note instead of a Sigma rule.

## vsftpd

With the default syslog target, `/var/log/auth.log` (Debian) or
`/var/log/secure` (RHEL) contains:

```
Nov  5 08:36:01 host vsftpd[2411]: [anonymous] OK LOGIN: Client "203.0.113.10"
Nov  5 08:36:07 host vsftpd[2413]: [anonymous] FTP response: Client "203.0.113.10", "230 Login successful."
```

Transfers, when `xferlog_enable=YES`:

```
Thu Nov  5 08:36:12 2026 1 203.0.113.10 1048576 /backup/site.zip b _ o a anonymous ftp 0 * c
```

Hunt for:

- any `OK LOGIN` where the user is `anonymous` or `ftp`
- a download of an archive (`*.zip`, `*.tar`, `*.gz`, `*.bak`) immediately after
  the login
- an `anonymous` session arriving from a country or ASN your staff never use

## proftpd

```
Nov 05 08:36:01 host proftpd[3121]: host (203.0.113.10[203.0.113.10]) - ANONYMOUS FTP LOGIN FROM 203.0.113.10, ...
```

Any `ANONYMOUS FTP LOGIN` line is the event; the file accessed follows in the
`RETR` line.

## Config check

```bash
grep -E '^\s*(anonymous_enable|anon_upload_enable|anon_mkdir_write_enable|anon_root)' \
  /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null
```

If `anonymous_enable=YES` is deliberate, the account should be read-only and its
root should contain nothing but the files you intend to publish. The lab box had
anonymous login enabled and a backup archive of the web application sitting in
the writable tree, which handed over the source code and a password hash.

## Blind spots

- Logs are per-daemon and often rotated quickly. Ship them off-host as soon as
  they are written.
- A compromised account that authenticates normally will not appear as
  anonymous; look for `RETR` of archives by any account, not only anonymous ones.
- TLS does not hide the login name from the server log.
