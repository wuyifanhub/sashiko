# Email Account Ingestion Design

## Overview

Sashiko supports fetching patches from email accounts via POP3/POP3S and IMAP/IMAPS protocols. This allows integration with mailing lists that forward patches via email.

## Architecture

```
Email Server (IMAPS/POP3S)
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│  ImapClient /   │────▶│  Event System    │
│  Pop3Client     │     │ (ArticleFetched) │
└─────────────────┘     └────────┬────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │    Ingestor     │
                        │ (do_imap_fetch) │
                        └─────────────────┘
```

## Protocol Support

| Protocol | Port | Encryption | Implementation |
|----------|------|-----------|----------------|
| POP3 | 110 | Plaintext | `pop3.rs` |
| POP3S | 995 | Implicit TLS | `pop3.rs` |
| IMAP | 143 | Plaintext | `imap.rs` |
| IMAPS | 993 | Implicit TLS | `imap.rs` |

## Configuration

Add email accounts to `Settings.toml`:

```toml
[[email_accounts]]
protocol = "imaps"           # pop3, pop3s, imap, imaps
server = "imap.xxxx.com"
port = 993
username = "user@xxxx.com"
password = "app_password"
mailbox = "INBOX"           # IMAP only
use_ssl = true
patch_filter = "PATCH"      # Subject keyword to filter
```

## Client Implementation

### POP3 Client (`src/pop3.rs`)

Pure Rust async implementation using tokio:

```rust
pub struct Pop3Client<S> {
    stream: tokio::io::BufReader<S>,
    state: Pop3State,
}

// Methods
impl Pop3Client<TcpStream> {
    pub async fn connect(host: &str, port: u16) -> Result<Self>
}

impl Pop3Client<TlsStreamWrapper> {
    pub async fn connect_ssl(host: &str, port: u16) -> Result<Self>
}
```

Key operations:
- `stat()` - Get mailbox status
- `list()` - List all messages with sizes
- `uidl()` - Get unique identifiers for deduplication
- `retr(msg_id)` - Retrieve full message
- `top(msg_id, lines)` - Retrieve headers + N body lines

### IMAP Client (`src/imap.rs`)

Similar architecture with tagged command support:

```rust
pub struct ImapClient<S> {
    stream: tokio::io::BufReader<S>,
    tag_counter: u32,
    state: ImapState,
}
```

Key operations:
- `login(user, pass)` - Authenticate
- `select(mailbox)` - Select mailbox, get message count
- `search(charset, criteria)` - Search messages (e.g., `SUBJECT "PATCH"`)
- `fetch(sequence, items)` - Fetch message data (BODY[], UID, etc.)

## Ingestor Integration

The `Ingestor` struct processes email accounts in `run_email_accounts()`:

```rust
async fn run_email_accounts(&self) -> Result<()>
async fn process_email_account(&self, account: &EmailAccountSettings) -> Result<()>
async fn do_imap_fetch<S>(&self, client: &mut ImapClient<S>, account: &EmailAccountSettings) -> Result<()>
async fn do_pop3_fetch<S>(&self, client: &mut Pop3Client<S>, account: &EmailAccountSettings) -> Result<()>
```

### Deduplication

- IMAP: Uses message sequence number as key (`imap:user@domain:msg_num`)
- POP3: Uses UID from UIDL command as key (`pop3:user@domain:uid`)

### Patch Filtering

Messages are filtered by Subject line containing the `patch_filter` keyword (default: "PATCH").

## TLS/SSL Implementation

Both clients use `native-tls` + `tokio-native-tls` for SSL/TLS:

```rust
pub struct TlsStreamWrapper {
    stream: tokio_native_tls::TlsStream<TcpStream>,
}

impl AsyncRead for TlsStreamWrapper { ... }
impl AsyncWrite for TlsStreamWrapper { ... }
```

## Testing

### Test Binary

```bash
# Build
cargo build --release
```

### Full Ingestion

```bash
# Run with tracking enabled
cargo run --release -- --no-api --no-ai --track
```

## Security Considerations

1. **Password Storage**: Store passwords securely; consider environment variables or secrets management
2. **SSL Verification**: TLS certificates are verified by the native-tls library
3. **Proxy Support**: Set `HTTP_PROXY`/`HTTPS_PROXY` environment variables for corporate proxies

## Limitations

1. POP3S connections may hang in some proxy configurations
2. IMAP SEARCH uses CHARSET UTF-8 by default
3. Message body fetch uses `BODY[]` which fetches the entire message
4. No support for IMAP IDLE (push notifications); polling every 60 seconds
