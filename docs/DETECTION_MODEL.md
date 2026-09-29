# Detection Model

## ADDED — MEDIUM

A path exists in the current scan but not in the signed baseline.

Possible causes include a legitimate deployment, attacker tool drop, persistence artifact, or new configuration.

Analyst action: verify provenance and change context before accepting a new baseline.

## MODIFIED — HIGH

A regular file's SHA-256 or file type differs from baseline.

Possible causes include application/configuration tampering, malicious binary replacement, web-shell modification, or an approved deployment.

Analyst action: correlate hashes with package/deployment history, process activity, endpoint telemetry, and change records.

## SYMLINK_CHANGED — HIGH

A monitored symbolic link now points to different target text.

The scanner hashes the link itself and does not traverse the target.

## METADATA_CHANGED — MEDIUM

Content is unchanged but security-relevant metadata differs:

- permission mode
- UID
- GID

Timestamp-only changes are not alerted.

## DELETED — HIGH

A baseline path is absent and no read/walk error covers that path.

Deletion is deliberately suppressed when the monitor lacks visibility.

## SCAN_ERROR — HIGH

A file or directory could not be safely inspected.

Examples:

- permission denied
- transient I/O failure
- file changes while hashing

This is a visibility failure and is never silently treated as a deletion.

## BASELINE_INTEGRITY_FAILURE — CRITICAL

The baseline is missing, malformed, signed with the wrong key, or modified without a valid HMAC.

The monitor aborts normal comparison rather than trusting corrupted state.

## Baseline acceptance

Investigated changes remain detections until an operator explicitly accepts the current state:

~~~bash
fim-monitor baseline accept --reason "Approved patch CHG-1042"
~~~

That creates a new baseline generation and records a BASELINE_ACCEPTED audit event.
