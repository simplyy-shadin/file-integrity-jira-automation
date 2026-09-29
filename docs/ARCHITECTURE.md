# Architecture

## Design goals

The monitor separates four concerns:

1. trusted baseline state,
2. filesystem observation and change classification,
3. immutable local security evidence,
4. external incident delivery.

Keeping them separate prevents a Jira outage from modifying or erasing what the monitor observed.

## Scanner

The scanner recursively walks the configured root without following directory symlinks.

Regular files are hashed through an open file descriptor and accepted only when size, modification time, inode, and device remain stable during hashing. On platforms that support O_NOFOLLOW, the file descriptor also resists a path being swapped to a symbolic link between inspection and open.

Symlinks are monitored by hashing their target text instead of following the target outside the trust boundary.

Snapshots contain:

- relative path
- SHA-256
- size
- permission mode
- UID
- GID
- nanosecond modification time
- file type

## Signed baseline

The baseline is canonical JSON protected by HMAC-SHA256.

Writes use:

1. a temporary file in the same directory,
2. flush,
3. fsync,
4. atomic replacement.

Normal monitoring refuses to compare a scan against an invalid baseline.

## Detection engine

The detector compares the trusted baseline with the current scan and never updates trust automatically.

Read failures remain SCAN_ERROR events. Known baseline paths beneath a failed scan scope are not reclassified as deleted.

## Event store

SQLite stores immutable security events separately from mutable delivery state.

Each event includes the previous event HMAC:

~~~text
chain_hash_n = HMAC(
    integrity_key,
    immutable_event_n + chain_hash_(n-1)
)
~~~

Changing an old event breaks chain verification.

Detection fingerprints include the baseline generation. Repeated scans of the same unresolved deviation are deduplicated, but the same change can be detected again after a legitimate baseline update creates a new generation.

## Jira delivery

Jira delivery reads due events from a separate delivery table.

Retryable conditions include rate limiting and server errors. Retry-After is honored when Jira returns it; otherwise exponential backoff with jitter is used.

Permanent errors and exhausted retry budgets are moved to dead-letter state.

## Trust boundary

The HMAC key is the local root of trust. It should be protected separately from the monitored tree.

A privileged attacker who obtains both the key and writable local state can forge evidence. Remote log forwarding or a hardened external evidence store is the natural production extension.
