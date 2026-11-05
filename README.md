# Detection rules from my lab work

Most Hack The Box writeups end at the flag. This repository is the other half:
the detections I would want if the same technique arrived on a network I was
responsible for.

Each rule comes from a box I actually completed, and the technique was executed
on the target before the rule was written. Nothing here is copied from another
writeup or generated from a technique list.

## Contents

| Rule | Detects | Log source |
|---|---|---|
| [`linux_postgres_spawns_shell.yml`](rules/linux_postgres_spawns_shell.yml) | `postgres` forking a shell or interpreter (`COPY ... TO PROGRAM`) | Linux process creation |
| [`linux_sudo_editor_spawns_shell.yml`](rules/linux_sudo_editor_spawns_shell.yml) | `sudo vi` (or another editor) spawning a root shell | Linux process creation |
| [`windows_browser_spawns_shell.yml`](rules/windows_browser_spawns_shell.yml) | Browser process starting `cmd.exe` / PowerShell (kiosk escape) | Windows process creation |
| [`aws_s3_anonymous_put_object.yml`](rules/aws_s3_anonymous_put_object.yml) | Unsigned S3 `PutObject` / `PutObjectAcl` / `DeleteObject` | AWS CloudTrail |

Hunting notes cover cases where the event is not in process telemetry:

- [PostgreSQL command execution](hunting/postgresql-command-execution.md):
  `pg_stat_activity`, statement logs, and which roles can execute OS commands.
- [S3 anonymous writes](hunting/s3-anonymous-writes.md): CloudTrail data events,
  server access logs, and the bucket policy that makes it possible.
- [Anonymous FTP](hunting/anonymous-ftp.md): vsftpd and proftpd log lines, and
  what a session that downloads an archive looks like.

## Validation

Every rule passes `sigma check` with no errors and no issues:

```console
$ sigma check rules/
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

The Windows rule also converts to a backend query, which is the real test that
field names are usable:

```console
$ sigma convert -t splunk -p sysmon rules/windows_browser_spawns_shell.yml
EventID=1 (ParentImage IN ("*\\msedge.exe", "*\\chrome.exe", "*\\firefox.exe",
"*\\iexplore.exe")) (Image IN ("*\\cmd.exe", "*\\powershell.exe",
"*\\pwsh.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\mshta.exe"))
```

CI runs `sigma check` on every push (see
[`.github/workflows/sigma-check.yml`](.github/workflows/sigma-check.yml)).

## Using them

```bash
pip install sigma-cli
pip install pySigma-backend-splunk pySigma-pipeline-sysmon  # or your backend

sigma convert -t splunk -p sysmon rules/windows_browser_spawns_shell.yml
sigma convert -t sentinel rules/aws_s3_anonymous_put_object.yml
```

Change the pipelines to match your collection: Sysmon and Windows event 4688
have different field names, and Linux process creation usually comes from
auditd or an EDR agent rather than Sysmon for Linux.

## Scope and honest limitations

- **Four rules is not a detection programme.** They cover techniques I have run
  by hand; there is no coverage claim beyond that.
- **False positives are listed per rule** because every one of them has a
  legitimate edge case. The browser rule is the loudest: enterprise launchers
  and some SSO plugins do spawn `cmd.exe` from a browser process.
- **The process-creation rules assume parent/child telemetry.** Security event
  4688 alone is enough on Windows if command-line auditing is on; plain
  `auditd` needs an `execve` rule with parent tracking.
- **The S3 rule is only as good as your data events.** CloudTrail does not log
  object-level API calls by default, so a bucket without data events and without
  access logging is blind to this.
- **These are lab-derived, not production-tuned.** Treat thresholds and
  suppression as a starting point, not a finished configuration.

## Related writeups

- [Vaccine](https://github.com/escanor155/htb-writeups/blob/main/starting-point/vaccine.md):
  anonymous FTP, a leaked hash, SQL injection as a superuser, and
  `COPY ... TO PROGRAM` to a shell.
- [Three](https://github.com/escanor155/htb-writeups/blob/main/starting-point/three.md):
  virtual host discovery, a public S3 bucket, anonymous write to the web root.

Written by [Anthony Salisi](https://github.com/escanor155).
