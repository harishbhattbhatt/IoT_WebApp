# ServiceBusReader

Minimal .NET 8 console client that receives file messages from an Azure Service Bus **queue**
(or an existing **topic subscription**), decrypts `AES-256-GCM/DP01` payloads, verifies them and
writes the original files to disk.

## Setup

```bash
cd ServiceBusReader
cp config.example.json config.json   # config.json is git-ignored
dotnet run
```

`config.json`:

| Key | Meaning |
|---|---|
| `ServiceBus:ConnectionString` | **Listen-only** connection string from the namespace owner |
| `ServiceBus:QueueName` | Queue to read (e.g. `temp`) |
| `ServiceBus:TopicName` / `SubscriptionName` | Use instead of `QueueName` if the entity is a topic |
| `ServiceBus:MaxConcurrentCalls` | Parallel message handlers (default 1) |
| `Decryption:KeyBase64` / `KeyFile` | 32-byte AES key (Base64), inline or from a file |
| `Output:Directory` | Where received files are written (default `received`) |

Every value can be overridden with environment variables, which is the preferred place for secrets:

```bash
export ServiceBus__ConnectionString="Endpoint=sb://..."
export Decryption__KeyBase64="..."
```

Never commit the key or connection string.

## Message handling

- `Subject = encrypted-file` and `encryption = AES-256-GCM/DP01`:
  body = `DP01` | nonce(12) | tag(16) | ciphertext, AAD = `DP01`.
  Plaintext = int32 LE metadata length | UTF-8 JSON (`fileName`, `fileExtension`, `contentType`,
  `fileSize`, `sha256`) | file bytes. Size and SHA-256 are verified; `fileName` is sanitized.
- `Subject = file` with no `encryption` property: body is the raw file, metadata from application properties.
- Anything else (unknown encryption, bad marker, auth-tag failure, checksum mismatch) is **abandoned**,
  so normal retry / dead-letter handling (`MaxDeliveryCount`) applies. Messages are completed only after
  the file has been written.
