# File Integrity Detection & Jira Incident Automation

A Blue Team / Detection Engineering project that establishes a **signed file baseline**, detects unauthorized filesystem changes, stores immutable tamper-evident security events, and reliably forwards incidents to Jira Cloud.

This is intentionally more than a checksum script. The project separates trusted state, detection, immutable security evidence, and incident delivery so an alerting outage cannot silently erase a file-integrity event.

## What the project demonstrates

- recursive SHA-256 file-integrity monitoring
- file creation, deletion, content-change, metadata-change, and symlink detection
- HMAC-signed baseline verification
- atomic baseline persistence
- explicit baseline initialization and acceptance
- stable file hashing with replacement/race checks
- scan-error handling that avoids false deletion alerts
- immutable SQLite security-event storage
- HMAC-linked tamper-evident event chaining
- per-baseline event deduplication
- structured JSON operational logging with rotation
- durable Jira delivery state
- Jira Cloud REST API v3 with Atlassian Document Format
- explicit HTTP timeouts
- Jira 429 Retry-After handling
- exponential retry/backoff and dead-letter handling
- configurable exclusions and environment-based secrets
- operator CLI for monitoring, verification, event review, and response
- multi-version Python CI with attack-focused tests

## Architecture

~~~text
                    Protected directory
                           |
                           v
                    Filesystem scanner
                           |
              +------------+-------------+
              |                          |
           SHA-256                    metadata
              |                 mode / UID / GID
              +------------+-------------+
                           |
                           v
                  Signed trusted baseline
                    HMAC-SHA256
                           |
                           v
                     Detection engine
          +---------+------+-------+----------+
          |         |              |          |
        ADDED    MODIFIED        DELETED   SCAN_ERROR
          |         |              |          |
          +---------+------+-------+----------+
                           |
                           v
                 Immutable security event
                           |
                  HMAC-linked event chain
                           |
                           v
                   SQLite event store
                           |
              +------------+-------------+
              |                          |
              v                          v
        local evidence              Jira delivery
                                      queue
                                        |
                             timeout / backoff / retry
                                        |
                                        v
                                  Jira incident
~~~

See [Architecture](docs/ARCHITECTURE.md), [Threat Model](docs/THREAT_MODEL.md), and [Detection Model](docs/DETECTION_MODEL.md).

## Trusted baseline workflow

The monitor does **not** replace its baseline after every scan.

That prevents this failure mode:

~~~text
file changed
    |
    v
Jira temporarily fails
    |
    v
baseline silently updated
    |
    v
next scan sees no change
~~~

Instead, deviations remain visible until an operator deliberately approves the current state:

~~~bash
fim-monitor baseline accept --reason "Approved deployment CHG-1042"
~~~

Baseline changes are themselves written to the local audit chain.

## Detection types

| Event | Meaning | Default severity |
|---|---|---:|
| ADDED | New path not present in baseline | MEDIUM |
| MODIFIED | File content or file type changed | HIGH |
| SYMLINK_CHANGED | Symbolic-link target changed | HIGH |
| METADATA_CHANGED | Mode, UID, or GID changed | MEDIUM |
| DELETED | Baseline path is genuinely absent | HIGH |
| SCAN_ERROR | File/directory could not be safely inspected | HIGH |
| BASELINE_INTEGRITY_FAILURE | Baseline HMAC verification failed | CRITICAL |

A read error is deliberately **not** treated as deletion.

## Tamper-evident event chain

Every immutable event records the previous event HMAC:

~~~text
GENESIS
   |
   v
Event 1 + previous hash -> HMAC 1
                           |
                           v
Event 2 + HMAC 1 --------> HMAC 2
                           |
                           v
Event 3 + HMAC 2 --------> HMAC 3
~~~

Run:

~~~bash
fim-monitor verify
~~~

to verify both the signed baseline and the local event chain.

## Jira incident delivery

Detection state and delivery state are separate.

~~~text
security event
    |
    v
persist locally
    |
    v
Jira attempt
    |
    +-- success ----------> delivered
    |
    +-- retryable --------> retry queue
    |                         |
    |                  Retry-After / backoff
    |
    +-- permanent/max ----> dead letter
~~~

The event ID is included in the Jira issue body as a correlation marker.

## Quick start

### 1. Clone and install

~~~bash
git clone https://github.com/simplyy-shadin/file-integrity-jira-automation.git
cd file-integrity-jira-automation

python -m venv .venv
source .venv/bin/activate
# Windows: .venv\Scripts\activate

pip install -e ".[dev]"
cp .env.example .env
~~~

### 2. Generate the local integrity key

~~~bash
python -c "import secrets; print(secrets.token_hex(32))"
~~~

Store the generated value in FIM_INTEGRITY_KEY. It is the root of trust for baseline signatures and event-chain verification and must not be committed.

### 3. Configure the monitored directory

~~~text
FIM_MONITOR_PATH=/absolute/path/to/protected/directory
FIM_STATE_DIR=.fim-state
FIM_INTERVAL_SECONDS=60
~~~

Runtime state should ideally live outside the protected directory. If the configured state directory is inside the monitored root, it is automatically excluded.

### 4. Configure Jira

~~~text
JIRA_ENABLED=true
JIRA_URL=https://your-domain.atlassian.net
JIRA_EMAIL=analyst@example.com
JIRA_API_TOKEN=<api token>
JIRA_PROJECT_KEY=SEC
JIRA_ISSUE_TYPE=Task
~~~

For local-only detection:

~~~text
JIRA_ENABLED=false
~~~

### 5. Establish trust

~~~bash
fim-monitor baseline init
~~~

The first baseline does not create a storm of "new file" Jira issues.

### 6. Check Jira connectivity

~~~bash
fim-monitor jira check
~~~

### 7. Scan or monitor

~~~bash
fim-monitor scan
fim-monitor monitor
~~~

## Operator commands

| Command | Purpose |
|---|---|
| fim-monitor baseline init | Establish initial trusted state |
| fim-monitor baseline init --force | Explicitly replace an existing baseline |
| fim-monitor baseline accept --reason "..." | Approve investigated current state |
| fim-monitor scan | Run one scan and process due Jira deliveries |
| fim-monitor scan --no-deliver | Persist detections without contacting Jira |
| fim-monitor monitor | Continuously scan |
| fim-monitor events --limit 50 | Review immutable local events |
| fim-monitor verify | Verify baseline signature and event HMAC chain |
| fim-monitor retry | Retry due Jira deliveries |
| fim-monitor jira check | Validate Jira authentication/connectivity |
| fim-monitor status | Show integrity and delivery-queue status |

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| FIM_MONITOR_PATH | Directory protected by the monitor | required |
| FIM_STATE_DIR | Baseline, database, and logs | .fim-state |
| FIM_INTERVAL_SECONDS | Continuous-monitor interval | 60 |
| FIM_INTEGRITY_KEY | HMAC root-of-trust key | required |
| FIM_EXCLUDE_PATTERNS | Additional comma-separated glob exclusions | empty |
| JIRA_ENABLED | Enable Jira delivery | true |
| JIRA_URL | Jira Cloud site URL | required when enabled |
| JIRA_EMAIL | Atlassian account email | required when enabled |
| JIRA_API_TOKEN | Atlassian API token | required when enabled |
| JIRA_PROJECT_KEY | Destination Jira project | required when enabled |
| JIRA_ISSUE_TYPE | Issue type | Task |
| JIRA_TIMEOUT_SECONDS | HTTP timeout | 10 |
| JIRA_MAX_ATTEMPTS | Delivery attempts before dead letter | 5 |

## Testing

~~~bash
ruff check .
pytest --cov=fim --cov-report=term-missing
~~~

GitHub Actions tests Python 3.11, 3.12, and 3.13 with an enforced coverage threshold.

The suite covers baseline tampering, wrong HMAC keys, malformed baselines, content/metadata/symlink changes, unreadable files, false-deletion conditions, duplicate detections, event-database tampering, Jira rate limits, Jira timeouts, delivery state, baseline acceptance, and configuration failures.

## Operational deployment

A hardened example systemd unit is provided at [deploy/fim-monitor.service](deploy/fim-monitor.service). See [Operations](docs/OPERATIONS.md) before using it.

## Security boundaries

This project makes the baseline and local event history **tamper-evident**, not tamper-proof.

An attacker with sufficient privilege to steal the HMAC key and rewrite local state can forge both. Production designs should protect the key outside the monitored tree and forward important evidence to a remote security system.

This is not an EDR, kernel monitor, remote-attestation system, or replacement for an enterprise FIM product. Polling also means a file created and removed entirely between scans may not be observed.

Jira issue creation is effectively at-least-once delivery. An ambiguous network failure after Jira accepts a request can theoretically produce a duplicate on a later retry; the event ID provides correlation.

## Portfolio focus

This repository demonstrates **Blue Team detection engineering, file-integrity monitoring, tamper-evident security telemetry, and incident-response automation**.

It intentionally stays distinct from DevSecOps pipeline security and application authentication projects.

## License

MIT License.
