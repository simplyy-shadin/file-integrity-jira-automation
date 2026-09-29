# Operations Guide

## Recommended filesystem layout

~~~text
/opt/file-integrity-jira-automation/    application
/etc/fim-monitor.env                    secrets/config
/var/lib/fim-monitor/                   baseline + SQLite state
/var/log/                               optional system journal export
~~~

Keep the state directory and environment file outside the monitored directory where practical.

## Bootstrap

1. Create a dedicated service account.
2. Give it read access to the protected tree.
3. Give it write access only to the FIM state directory.
4. Store the environment configuration in a root-owned file.
5. Generate the integrity key with a cryptographically secure generator.
6. Initialize the baseline after verifying the host is in a trusted state.
7. Test Jira connectivity.
8. Start monitoring.

Example:

~~~bash
sudo install -d -o fim-monitor -g fim-monitor /var/lib/fim-monitor
sudo install -m 600 .env.example /etc/fim-monitor.env

fim-monitor baseline init
fim-monitor jira check
fim-monitor verify
~~~

## Routine incident workflow

When Jira reports a change:

1. preserve the FIM event ID,
2. inspect old/new hashes and metadata,
3. correlate with change-management records,
4. examine endpoint/process/package history,
5. determine whether the change is authorized,
6. remediate unauthorized changes,
7. only after validation, accept the intended current state as the new baseline.

~~~bash
fim-monitor baseline accept --reason "Validated deployment CHG-1042"
~~~

## Dead-letter queue

A dead-letter Jira delivery means the local security event still exists but automated incident delivery has stopped retrying.

Check:

~~~bash
fim-monitor status
fim-monitor events --limit 50
fim-monitor jira check
~~~

Fix configuration/permissions, then investigate whether the event needs manual Jira creation.

## Key rotation

The HMAC key signs both the baseline and event chain. Rotating it requires deliberate migration or re-establishing trust; simply changing the environment variable makes historical signatures fail.

For a portfolio/lab deployment, the safest simple approach is:

1. archive/export evidence you need,
2. stop monitoring,
3. protect and record the old key if historical verification is required,
4. configure the new key,
5. initialize a new baseline and event store,
6. document the rotation.

Production designs should use formal key management rather than ad-hoc environment-file rotation.

## systemd

The example service file assumes:

- application installed under /opt/file-integrity-jira-automation
- virtualenv under /opt/file-integrity-jira-automation/.venv
- environment file at /etc/fim-monitor.env
- state at /var/lib/fim-monitor

Review all paths and permissions before enabling the service.
