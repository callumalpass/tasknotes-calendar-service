# Data classification and initial retention

| Data                             | Class               |                               Initial retention | Notes                                                        |
| -------------------------------- | ------------------- | ----------------------------------------------: | ------------------------------------------------------------ |
| Google issuer and subject        | Identity-sensitive  |                          Until account deletion | Authoritative identity key; never a metric label             |
| Email and display name           | Personal            |                          Until account deletion | Display only; not authorization                              |
| Device session digest            | Credential verifier |                   30-day idle / 90-day absolute | Raw credential returned once and never persisted             |
| OAuth transaction digests        | Security-sensitive  |           10 minutes plus bounded cleanup delay | No raw state, nonce, polling secret, or client verifier      |
| Encrypted provider PKCE verifier | Secret ciphertext   |                            Transaction lifetime | Context-bound; deleted at terminal cleanup                   |
| Google token envelope            | Secret ciphertext   | Until disconnect/deletion/reconnect replacement | Application-layer AEAD; no plaintext fallback                |
| Calendar metadata                | Personal            |          Until disconnect/deletion; refreshable | Raw provider calendar ID remains server-side                 |
| Live normalized event response   | Calendar content    |                                    Not retained | No event mirror, mapping table, or cache                     |
| Event ID derivation key          | Secret              |    Environment lifetime; non-rotating by design | Dedicated key; compromise replacement changes all event IDs  |
| Request/audit metadata           | Operational         |                               Define before LAB | Opaque internal IDs only; no email/event/provider token data |

Retention values are implementation defaults, not permission to retain data in logs or backups.
Backup and Cloudflare platform-retention behavior must be documented before real-user testing.
