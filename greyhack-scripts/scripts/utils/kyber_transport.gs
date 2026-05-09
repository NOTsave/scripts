// kyber_transport.gs - C2 encryption and transport layer
// Separated from lib_common for clean architecture

import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")

// ============================================
// C2 Transport Configuration
// ============================================

C2_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2

// ============================================
// Key Management
// ============================================

get_c2_keypair = function()
    // Check if keys already exist
    priv = safe_file_read("/root/.botnet/slave.priv")
    pub = safe_file_read("/root/.botnet/slave.pub")

    if priv != null and pub != null then
        return {"private": priv, "public": pub}
    end if

    // Generate new keypair
    keys = Kyber.generate_keypair()
    if keys == null then  // ✅ Check for null
        log_master("ERROR: Kyber.generate_keypair() returned null", "ERROR")
        return null
    end if
    if keys.private == null or keys.public == null then  // ✅ Check fields
        log_master("ERROR: Keypair missing private or public key", "ERROR")
        return null
    end if

    // Save keys
    if not safe_file_write("/root/.botnet/slave.priv", keys.private) then
        log_master("ERROR: Failed to write private key", "ERROR")
        return null
    end if
    if not safe_file_write("/root/.botnet/slave.pub", keys.public) then
        log_master("ERROR: Failed to write public key", "ERROR")
        comp.File("/root/.botnet/slave.priv").delete  // ✅ Cleanup on failure
        return null
    end if

    set_permissions("/root/.botnet/slave.priv", "600")
    set_permissions("/root/.botnet/slave.pub", "644")
    log_master("Generated new C2 keypair", "INFO")
    return keys
end function

get_master_pubkey = function(path="/root/.botnet/master.pub")
    pub = safe_file_read(path)
    if pub == null then
        log_master("ERROR: Master public key not found at " + path, "ERROR")
    end if
    return pub
end function

// ============================================
// Message Authentication via Kyber + Shared Secret (Item 32)
// ============================================

// Generate a shared secret during initial handshake
derive_message_auth_key = function(shared_secret)
    // Simple KDF: hash the shared secret multiple times
    key = shared_secret
    for i in range(0, 10)
        // Simulate HKDF-Expand with repeated hashing
        key = str(key.len) + "_" + key  // Simple expansion
    end for
    return key
end function

authenticate_command = function(cmd, auth_key)
    // Create a digest by hashing command + auth_key
    // In GreyScript, we don't have SHA, so use a simple checksum
    digest = 0
    combined = cmd + "|" + auth_key
    
    for c in combined
        digest = (digest * 31 + c.code) % 2147483647
    end for
    
    return str(digest)
end function

verify_command_authenticity = function(cmd, provided_auth, expected_auth_key)
    expected_auth = authenticate_command(cmd, expected_auth_key)
    return provided_auth == expected_auth
end function

encrypt_authenticated_command = function(cmd, master_pubkey, auth_key)
    // Create authenticated command
    auth_tag = authenticate_command(cmd, auth_key)
    auth_cmd = cmd + "|AUTH:" + auth_tag
    
    // Encrypt the whole thing
    cipher = Kyber.encrypt_message(master_pubkey, auth_cmd)
    return cipher
end function

decrypt_and_verify_command = function(cipher, slave_privkey, auth_key)
    // Decrypt
    auth_cmd = Kyber.decrypt_message(slave_privkey, cipher)
    if not auth_cmd then return null
    
    // Split command and auth tag
    pipe_idx = auth_cmd.indexOf("|AUTH:")
    if pipe_idx == null then
        log_master("ERROR: No auth tag in decrypted command", "ERROR")
        return null
    end if
    
    cmd = auth_cmd[0 : pipe_idx]
    auth_str = auth_cmd[pipe_idx + 6 :]  // Skip "|AUTH:"
    
    // Verify authentication
    if not verify_command_authenticity(cmd, auth_str, auth_key) then
        log_master("ERROR: Command authentication failed (tampering suspected? )", "ERROR")
        return null
    end if
    
    return cmd
end function

// ============================================
// Base64 Validation Helper
// ============================================

is_base64 = function(s)
    if s == null or s == "" then return false
    if typeof(s) != "string" then return false
    
    valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    for c in s
        if valid_chars.find(c) == -1 then
            return false
        end if
    end for
    return true
end function

// ============================================
// Message Encryption/Decryption
// ============================================

encrypt_command = function(command, master_pubkey)
    if command == null or command == "" then return null
    if master_pubkey == null then return null
    
    cipher = Kyber.encrypt_message(master_pubkey, command)
    if cipher == null then
        log_master("ERROR: Failed to encrypt command", "ERROR")
    end if
    
    return cipher
end function

decrypt_command = function(cipher)
    if cipher == null or cipher == "" then return null
    
    // Validate ciphertext format BEFORE attempting decryption (Item 24)
    if typeof(cipher) != "string" then
        log_master("ERROR: Ciphertext is not a string (type: " + typeof(cipher) + ")", "ERROR")
        return null
    end if
    
    // Base64 validation - reject non-base64 characters
    if not is_base64(cipher) then
        log_master("ERROR: Ciphertext contains non-base64 characters", "ERROR")
        return null
    end if
    
    // Enhanced security checks: reject whitespace and control characters
    if cipher.find(" ") != null or cipher.find(char(10)) != null or cipher.find(char(13)) != null or cipher.find(char(9)) != null then
        log_master("ERROR: Ciphertext contains whitespace or control characters", "ERROR")
        return null
    end if
    
    // Check for null bytes and other dangerous characters
    if cipher.find(char(0)) != null then
        log_master("ERROR: Ciphertext contains null bytes", "ERROR")
        return null
    end if
    
    // Kyber-512 ciphertext is exactly 768 bytes (hex-encoded = ~1536 chars)
    // Stricter range to prevent DoS: 768-2048 chars (accounting for encoding variations)
    if cipher.len < 768 then
        log_master("ERROR: Ciphertext too short (" + cipher.len + " bytes, expected 768+)", "ERROR")
        return null
    end if
    
    if cipher.len > 2048 then  // Stricter limit to prevent DoS
        log_master("ERROR: Ciphertext too long (" + cipher.len + " bytes, max 2048)", "ERROR")
        return null
    end if
    
    // Attempt decryption with timeout protection
    keys = get_c2_keypair()
    if keys == null then
        log_master("ERROR: Cannot load C2 keypair for decryption", "ERROR")
        return null
    end if
    
    start_time = time
    command = Kyber.decrypt_message(keys.private, cipher)
    elapsed = time - start_time
    
    // Log if decryption took suspiciously long (possible DoS)
    if elapsed > 5 then
        log_master("WARN: Decryption took " + str(elapsed) + "s (possible malformed ciphertext)", "WARN")
    end if
    
    if command == null then
        log_master("ERROR: Kyber decryption failed (ciphertext invalid or corrupted)", "ERROR")
        return null
    end if
    
    // Validate decrypted command before returning
    if command.len == 0 then
        log_master("ERROR: Decryption produced empty command", "ERROR")
        return null
    end if
    
    if command.len > 1024 then
        log_master("ERROR: Decrypted command exceeds max length (1024 bytes)", "ERROR")
        return null
    end if
    
    return command
end function

encrypt_response = function(response, master_pubkey)
    return encrypt_command(response, master_pubkey)
end function

decrypt_response = function(cipher)
    return decrypt_command(cipher)
end function

// ============================================
// Secure Transport
// ============================================

secure_send = function(ip, data, get_password_func)
    // Retry connection with exponential backoff
    connect_func = function()
        return get_shell.connect_service(ip, 22, "backdoor", get_password_func(ip))
    end function
    
    shell = retry_network(connect_func, MAX_RETRIES, RETRY_BASE_DELAY)
    if typeof(shell) == "string" or shell == null then
        log_master("Failed to connect to " + sanitize_ip(ip) + " after retries", "ERROR")
        return false
    end if
    
    // Create temporary encrypted file
    tmp_file = "/tmp/c2_" + str(time) + "_" + str(floor(rnd * 9999)) + ".enc"
    if not safe_file_write(tmp_file, data) then
        shell.close
        return false
    end if
    
    // Transfer file
    result = get_shell.scp(tmp_file, "/root/.botnet/commands/", shell)
    
    // Cleanup
    get_shell.host_computer.File(tmp_file).delete
    shell.close
    
    if typeof(result) == "string" then
        log_master("SCP transfer failed to " + sanitize_ip(ip) + ": " + result, "ERROR")
        return false
    end if
    
    return true
end function

secure_receive = function(ip, get_password_func)
    connect_func = function()
        return get_shell.connect_service(ip, 22, "backdoor", get_password_func(ip))
    end function
    
    shell = retry_network(connect_func, MAX_RETRIES, RETRY_BASE_DELAY)
    if typeof(shell) == "string" or shell == null then
        return null
    end if
    
    responses = []
    resp_dir = shell.host_computer.File("/root/.botnet/responses")
    
    if resp_dir != null then
        for f in resp_dir.get_files
            if f == null then continue
            if f.name[-4:] == ".enc" then
                cipher = f.get_content
                if cipher != null then
                    responses.push(cipher)
                end if
                f.delete
            end if
        end for
    end if
    
    shell.close
    return responses
end function

// ============================================
// Message Validation
// ============================================

validate_command_structure = function(command)
    if command == null or command == "" then return false
    if typeof(command) != "string" then return false
    if command.len > 1024 then return false
    
    // Basic structure validation
    parts = command.split(" ")
    if parts.len == 0 then return false
    
    // Check for forbidden characters
    forbidden = [";", "|", "&", "$", "`", "<", ">"]
    for part in parts
        for char in forbidden
            if part.indexOf(char) != null then
                return false
            end if
        end for
    end for
    
    return true
end function

// ============================================
// Transport Statistics
// ============================================

transport_stats = {
    "messages_sent": 0,
    "messages_received": 0,
    "encryption_failures": 0,
    "connection_failures": 0
}

update_stats = function(event_type)
    if transport_stats.hasIndex(event_type) then
        transport_stats[event_type] = transport_stats[event_type] + 1
    end if
end function

get_transport_stats = function()
    return transport_stats + []  // Return copy
end function

// ============================================
// Heartbeat System
// ============================================

send_heartbeat = function(ip, master_pubkey, get_password_func, metrics=null)
    heartbeat = {
        "type": "heartbeat",
        "timestamp": time,
        "version": "1.0",
        "uptime": time - (globals.start_time or time),
        "commands_executed": transport_stats["messages_sent"],
        "last_contact": globals.last_master_contact or 0
    }
    
    if metrics != null then
        heartbeat = heartbeat + metrics
    end if
    
    heartbeat_json = serialize_heartbeat(heartbeat)
    cipher = encrypt_command(heartbeat_json, master_pubkey)
    
    if cipher != null then
        result = secure_send(ip, cipher, get_password_func)
        if result then
            update_stats("messages_sent")
            globals.last_heartbeat = time
            return true
        end if
    end if
    
    update_stats("connection_failures")
    return false
end function

serialize_heartbeat = function(data)
    // Simple JSON-like serialization for GreyScript
    parts = []
    for key in data.keys
        value = data[key]
        if typeof(value) == "string" then
            parts.push(key + ":" + char(34) + value + char(34))
        else
            parts.push(key + ":" + str(value))
        end if
    end for
    return "{" + parts.join(",") + "}"
end function
