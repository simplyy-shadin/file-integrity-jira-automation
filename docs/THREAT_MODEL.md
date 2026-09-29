# Threat Model

## Protected assets

- monitored file contents
- file ownership and permission metadata
- signed baseline
- HMAC integrity key
- immutable security-event history
- Jira API credentials
- delivery status and external incident references

## Abuse cases

| Threat | Attack path | Control |
|---|---|---|
| File tampering | Modify protected file | SHA-256 comparison against signed baseline |
| Binary replacement | Swap executable/configuration | Content hash and file-type detection |
| Permission abuse | chmod/chown without content change | mode/UID/GID comparison |
| Symlink redirection | Replace link target | symlink-target hashing |
| Baseline editing | Modify baseline JSON | HMAC verification; monitoring aborts on failure |
| Evidence editing | Rewrite SQLite security event | HMAC-linked event-chain verification |
| Alert suppression via Jira outage | Break Jira/API connectivity | event persisted before delivery; retry/dead-letter state |
| Alert storm | Same unresolved deviation every scan | per-baseline detection fingerprint deduplication |
| False deletion | Make path temporarily unreadable | scan errors suppress deletion classification |
| First-run ticket storm | Empty baseline sees all files as new | explicit baseline initialization mode |
| Secret disclosure | Commit Jira/HMAC secrets | environment config and gitignore |
| Rate limiting | Jira returns 429 | Retry-After + backoff |
| API/server outage | Jira 5xx/network failure | durable retry queue |
| Historical state corruption | Crash while baseline is written | temp write + fsync + atomic replace |
| Path-race attack | File replaced while hashing | descriptor hashing, stability checks, O_NOFOLLOW where available |

## Trust assumptions

The local HMAC key is trusted. If an attacker gains sufficient privilege to read that key and modify local state, the attacker can forge a valid baseline or event chain.

The operating system, Python runtime, and cryptographic libraries are also in the trusted computing base.

Jira is an incident-management destination, not the primary forensic evidence store.

## Known limitations

### Polling gap

A file that is created, used, and removed entirely between two scans may not be observed.

### Local root compromise

The design is tamper-evident against unauthorized state edits without the HMAC key, but it is not resistant to a fully privileged attacker who steals the key.

### At-least-once external delivery

A network timeout after Jira has accepted an issue is ambiguous. A later retry can theoretically create a duplicate incident. The immutable FIM event ID is included in the issue for correlation.

### Not an EDR

The project does not provide process ancestry, memory telemetry, kernel events, remote attestation, or malware prevention.
