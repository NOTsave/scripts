# Botnet API Reference

## Core Functions

### `safe_path(path: string) -> bool` 
Validates that a file path is within allowed botnet directories.

**Allowed directories:**
- `/root/.botnet/` — botnet data and state
- `/scripts/utils/` — utility scripts
- `/scripts/tools/` — utility tools
- `/bin/` — executable binaries
- `/lib/` — shared libraries
- `/tmp/` — temporary files

**Security:**
- Prevents directory traversal via `..` sequences
- Rejects environment variables `$VAR` and command substitution `` ` ``
- Rejects shell metacharacters in path components
- Normalizes paths to prevent double-dot bypasses

**Example:**
```greyscript
if safe_path("/root/.botnet/infected.txt") then
    // safe to read
end if
```

### `validate_command(cmd: string) -> bool` 
Validates command structure and arguments before execution.

**Allowed commands:**
- `run <script> [args...]` — execute a script
- `kill <script>` — stop a running script
- `status` — get bot status
- `clean` — wipe logs
- `read <file>` — read a file
- `update` — update bot code
- `worm <pubkey_path> <depth>` — launch worm
- `rotate` — rotate watchdog names
- `help` — show help

**Validation rules:**
- Command must be in allowed list
- Script paths must be in whitelist
- Worm depth must be 0-10
- No shell metacharacters allowed
- Total command length < 1024 bytes

### `Kyber.encrypt_message(pubkey: string, message: string) -> string | null` 
Encrypts a message with post-quantum encryption (CRYSTALS-Kyber-512).

**Parameters:**
- `pubkey` — recipient's public key
- `message` — plaintext to encrypt (max 10000 bytes)

**Returns:**
- Encrypted ciphertext (hex-encoded)
- `null` on failure

**Security:**
- IND-CCA2 secure (resists chosen ciphertext attacks)
- Post-quantum resistant (believed secure against quantum computers)

### `Kyber.decrypt_message(privkey: string, cipher: string) -> string | null` 
Decrypts a Kyber-encrypted ciphertext.

**Parameters:**
- `privkey` — recipient's private key
- `cipher` — hex-encoded ciphertext

**Returns:**
- Decrypted plaintext
- `null` on failure

**Security:**
- Decryption can fail if ciphertext is modified or malformed
- Never logs the plaintext (security best practice)

## Utility Functions

### `log_master(message: string, level: string) -> void` 
Logs a message with timestamp, level, and module name.

**Levels:**
- `"DEBUG"` — detailed diagnostic info
- `"INFO"` — general informational messages
- `"WARN"` — warning (recoverable error)
- `"ERROR"` — error (unrecoverable, may crash)
- `"SUCCESS"` — successful operation

**Example:**
```greyscript
log_master("Bot started", "INFO")
log_master("Exploitation failed on " + target, "WARN")
```

### `sanitize_ip(ip: string) -> string` 
Masks IP address for display/logging (prevents accidental leakage).

**Example:**
```greyscript
log_master("Infecting " + sanitize_ip(target_ip), "INFO")
// Logs: "Infecting [REDACTED]"
```

### `write_file(path: string, content: string) -> bool` 
Writes content to a file, creating directories as needed.

**Returns:** `true` on success, `false` on failure

**Example:**
```greyscript
if write_file("/root/.botnet/infected.txt", infected.join(char(10))) then
    log_master("Wrote infected list", "INFO")
else
    log_master("ERROR: Failed to write infected list", "ERROR")
end if
```

## Security Best Practices

### Command Formatting
Always include timestamp and nonce to prevent replay:
```greyscript
nonce = generate_nonce()
cmd_with_meta = str(time) + ":" + nonce + ":" + raw_command
cipher = Kyber.encrypt_message(pubkey, cmd_with_meta)
```

### Path Validation
Always call `safe_path()` before file operations:
```greyscript
if not safe_path(user_provided_path) then
    log_master("ERROR: Unsafe path " + user_provided_path, "ERROR")
    return null
end if
```

### Error Handling
Always check for null/errors:
```greyscript
content = read_file(path)
if content == null then
    log_master("ERROR: File not found: " + path, "ERROR")
    return false
end if
```

## Authentication Functions

### `validate_command_with_replay_protection(cmd_with_meta: string) -> string | null`
Validates command includes timestamp and nonce, prevents replay attacks.

**Parameters:**
- `cmd_with_meta` — Command in format "TIMESTAMP:NONCE:COMMAND"

**Returns:**
- Extracted command if valid
- `null` if invalid or replay detected

### `encrypt_authenticated_command(cmd: string, master_pubkey: string, auth_key: string) -> string | null`
Encrypts command with authentication tag.

**Parameters:**
- `cmd` — Command to encrypt
- `master_pubkey` — Master's public key
- `auth_key` — Shared secret for authentication

## Glossary

- **Nonce**: Number used once; prevents replay attacks
- **IND-CCA2**: Indistinguishability under Chosen Ciphertext Attack (gold standard for encryption)
- **KEM**: Key Encapsulation Mechanism; like TLS key exchange but quantum-resistant
- **Depth**: Worm propagation level; 0 = initial infection, 5 = max safe depth
- **Replay Attack**: Attacker captures and re-sends valid encrypted commands
- **Command Injection**: Malicious input that alters shell command execution
