// ======================================
// lib_common.gs
// Shared utilities: logging, file ops,
// encryption wrappers, retry logic
// Dependencies: kyber_lib.gs
// ======================================

// Guard block: prevent double-import issues and globals re-initialization
if globals.hasIndex("lib_common_loaded") then
    return
end if
globals.lib_common_loaded = true

red = function(str) return "<color=#c30000><b>" + str + "</b></color>" end function
green = function(str) return "<color=#00c300><b>" + str + "</b></color>" end function
yellow = function(str) return "<color=#ffff00><b>" + str + "</b></color>" end function
blue = function(str) return "<color=#85b8ff><b>" + str + "</b></color>" end function
white = function(str) return "<color=#eeeeee><b>" + str + "</b></color>" end function

rotate_log = function(log_path=null, max_size_mb=10)
    if log_path == null then log_path = get_config("paths.botnet_root") + "/log.txt"
    comp = get_shell.host_computer
    f = comp.File(log_path)
    if not f then return
    if f.size > max_size_mb * 1024 * 1024 then
        old_size = f.size
        backup = comp.File(log_path + ".1")
        if backup then
            backup.set_content(f.get_content())
        else
            // Create backup file if it doesn't exist
            parts = log_path.split("/")
            filename = parts.pop() + ".1"
            dir = parts.join("/")
            if dir == "" then dir = "/"
            comp.touch(dir, filename)
            comp.File(log_path + ".1").set_content(f.get_content())
        end if
        f.set_content("")
        print("[rotate_log] Log rotated (was " + old_size + " bytes)")
    end if
end function

globals.log_level = "INFO"
globals.current_script = "unknown"
globals.log_write_count = 0
globals.log_buffer = []
globals.log_buffer_size = 50

flush_log_buffer = function()
    if globals.log_buffer.len == 0 then return
    
    comp = get_shell.host_computer
    log_path = get_config("paths.botnet_root") + "/log.txt"
    log_file = comp.File(log_path)
    if not log_file then
        comp.create_folder("/root", ".botnet")
        comp.touch("/root/.botnet", "log.txt")
        log_file = comp.File(log_path)
    end if
    
    if log_file then
        current_content = log_file.get_content
        if current_content == null then current_content = ""
        new_content = current_content + globals.log_buffer.join("")
        log_file.set_content(new_content)
        globals.log_buffer = []
        globals.log_write_count = globals.log_write_count + globals.log_buffer_size
        if globals.log_write_count % 100 == 0 then rotate_log()
    end if
end function

log_master = function(msg, level)
    if level == null then level = "INFO"
    levels = {"DEBUG":0, "INFO":1, "WARN":2, "ERROR":3}
    min_lvl = levels[globals.log_level]
    if min_lvl == null then min_lvl = 1
    if levels[level] < min_lvl then return
    
    timestamp = current_date + " " + str(time % 86400)
    entry = "[" + timestamp + "] [" + level + "] [" + globals.current_script + "] " + msg + char(10)
    
    globals.log_buffer.push(entry)
    
    if globals.log_buffer.len >= globals.log_buffer_size then
        flush_log_buffer()
    end if
    
    if level == "ERROR" then
        print(red(msg))
    else if level == "WARN" then
        print(yellow(msg))
    else if level == "SUCCESS" then
        print(green(msg))
    else
        print(white(msg))
    end if
end function

sanitize_input = function(input)
    if input == null then return ""
    if typeof(input) != "string" then return ""
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_/ "
    result = ""
    for c in input
        if allowed.indexOf(c) != null then result = result + c
        if result.len >= 256 then break
    end for
    return result
end function

write_file = function(path, content)
    comp = get_shell.host_computer
    parts = path.split("/")
    filename = parts.pop()
    dir_path = parts.join("/")
    if not comp.File(dir_path) then
        current = ""
        for part in parts
            if part == "" then continue
            current = current + "/" + part
            if not comp.File(current) then
                parent = current.split("/")[:-1].join("/")
                if parent == "" then parent = "/"
                result = comp.create_folder(parent, part)
                if typeof(result) == "string" then return false
            end if
        end for
    end if
    comp.touch(dir_path, filename)
    f = comp.File(path)
    if f then f.set_content(content)
    return f != null
end function

// read_file is now an alias for safe_file_read to avoid duplication
read_file = function(path)
    return safe_file_read(path)
end function

get_pids = function(script_name)
    comp = get_shell.host_computer
    ps = comp.show_procs
    pids = []
    for line in ps.split(char(10))[1:]
        if line == "" then continue
        parts = line.split(" ")
        if parts.len < 2 then continue
        if parts[-1] == script_name then pids.push(parts[1].to_int)
    end for
    return pids
end function

kill_all = function(script_name)
    for pid in get_pids(script_name)
        get_shell.host_computer.close_program(pid)
    end for
end function

backoff_sleep = function(attempt, base=2, max=300)
    delay = base * (2 ^ attempt)
    if delay > max then delay = max
    wait(delay)
end function

// XOR obfuscation (defense-in-depth) - deprecated, kept only for migration
xor_obfuscate = function(data, key)
    if data == null then return ""
    if key == null then return data
    if key == "" then return data
    if typeof(data) != "string" then data = str(data)
    if typeof(key) != "string" then key = str(key)
    
    // Guard against empty key causing division by zero
    if key.len == 0 then return data
    
    // Max 100KB input
    if data.len > 102400 then
        return data
    end if
    
    result = ""
    key_len = key.len
    
    for i in range(0, data.len - 1)
        key_char = key[i % key_len]
        result = result + char(data[i].code ^ key_char.code)
    end for
    
    return result
end function

generate_random_string = function(len)
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    result = ""
    for i in range(0, len-1)
        result = result + chars[floor(rnd * chars.len)]
    end for
    return result
end function

// ============================================
// Kyber-only password storage (XOR deprecated)
// Migration from XOR handled separately
// ============================================

// Store password encrypted with Kyber
store_password_kyber = function(file_path, password)
    if password == null or password == "" then return false
    if file_path == null or file_path == "" then return false
    
    comp = get_shell.host_computer
    
    // Get encryption key — try slave.pub first, then passkey.pub
    pub = safe_file_read("/root/.botnet/slave.pub")
    if pub == null then
        pub = safe_file_read("/root/.botnet/passkey.pub")
    end if
    
    if pub == null then
        log_master("ERROR: No public key available for password encryption", "ERROR")
        return false
    end if
    
    cipher = Kyber.encrypt_message(pub, password)
    if cipher == null then
        log_master("ERROR: Kyber encryption failed for password", "ERROR")
        return false
    end if
    
    if not safe_file_write(file_path, cipher) then
        log_master("ERROR: Failed to write encrypted password", "ERROR")
        return false
    end if
    
    set_permissions(file_path, "600")
    return true
end function

// Retrieve password encrypted with Kyber
retrieve_password_kyber = function(file_path)
    if file_path == null or file_path == "" then return null
    
    cipher = safe_file_read(file_path)
    if cipher == null then return null
    
    // Try slave private key first, then passkey private key
    priv = safe_file_read("/root/.botnet/slave.priv")
    if priv == null then
        priv = safe_file_read("/root/.botnet/passkey.priv")
    end if
    
    if priv == null then
        log_master("ERROR: No private key available for password decryption", "ERROR")
        return null
    end if
    
    password = Kyber.decrypt_message(priv, cipher)
    if password == null then
        log_master("ERROR: Kyber decryption failed for password", "ERROR")
        return null
    end if
    
    return password
end function

// One-time migration from XOR to Kyber
// Call during master initialization, after slave keypair is available
migrate_xor_passwords_to_kyber = function()
    comp = get_shell.host_computer
    botnet_dir = comp.File("/root/.botnet")
    
    if botnet_dir == null then return false
    
    files = botnet_dir.get_files
    if files == null then return true  // No files to migrate
    
    migrated_count = 0
    
    for f in files
        if f == null then continue
        
        // Look for legacy XOR password files: backdoor_pass_<IP>
        if f.name.indexOf("backdoor_pass_") == 0 and f.name.indexOf(".enc") == -1 then
            ip = f.name[15:]  // Extract IP from filename
            
            // Read XOR-encrypted password
            xor_data = f.get_content
            if xor_data == null or xor_data == "" then continue
            
            // Decrypt XOR
            password = xor_obfuscate(xor_data, "botnet_key_2026")
            if password == null or password == "" then continue
            
            // Encrypt with Kyber
            kyber_path = "/root/.botnet/backdoor_pass_" + ip + ".enc"
            if store_password_kyber(kyber_path, password) then
                // Delete original XOR file
                f.delete
                migrated_count = migrated_count + 1
                log_master("Migrated password for " + ip + " to Kyber", "INFO")
            else
                log_master("Failed to migrate password for " + ip, "WARN")
            end if
        end if
    end for
    
    if migrated_count > 0 then
        log_master("Password migration complete: " + str(migrated_count) + " passwords migrated", "SUCCESS")
    end if
    
    return true
end function

set_permissions = function(path, perms)
    // GreyScript has no native chmod - this is a no-op placeholder
    // File permissions in Grey Hack are managed by the game's file system
    // The perms parameter is kept for API compatibility but ignored
    return true
end function

// Simple BUFFER system inspired by 5hell's malp
globals.BUFFER = []

buffer_push = function(obj)
    globals.BUFFER.push(obj)
    return globals.BUFFER.len - 1  // Return index
end function

buffer_get = function(index)
    if globals.BUFFER.hasIndex(index) then
        return globals.BUFFER[index]
    end if
    return null
end function

buffer_list = function()
    result = "BUFFER contents (" + globals.BUFFER.len + " items):\n"
    for i in range(0, globals.BUFFER.len - 1)
        obj = globals.BUFFER[i]
        obj_type = typeof(obj)
        if obj_type == "shell" then
            result = result + "[" + i + "] shell -> " + obj.host_computer.public_ip + "\n"
        else if obj_type == "file" then
            result = result + "[" + i + "] file -> " + obj.path + "\n"
        else
            result = result + "[" + i + "] " + obj_type + "\n"
        end if
    end for
    return result
end function

buffer_clear = function()
    globals.BUFFER = []
    log_master("BUFFER cleared", "INFO")
end function

buffer_size = function()
    return globals.BUFFER.len
end function

// Safe file helpers for better resource management
safe_file_read = function(path)
    f = get_shell.host_computer.File(path)
    if f == null then return null
    content = f.get_content
    return content
end function

// ============================================
// Safe file write with directory creation
// Returns: true on success, false on failure
// ============================================

safe_file_write = function(path, content)
    if path == null or path == "" then return false
    if content == null then content = ""
    
    comp = get_shell.host_computer
    if comp == null then return false
    
    // Parse path
    parts = path.split("/")
    if parts.len < 2 then return false
    
    // Extract filename (last element) — BUG FIX: Use variable, not pop()()
    filename = parts[parts.len - 1]
    parts.pop  // Remove filename from path
    
    // Reconstruct directory path
    dir_path = parts.join("/")
    if dir_path == "" then dir_path = "/"
    
    // Verify parent directory exists or can be created
    parent = comp.File(dir_path)
    if parent == null then
        // Parent doesn't exist — attempt to create it
        // This is recursive: create intermediate directories if needed
        if not ensure_directory_exists(dir_path) then
            return false
        end if
    end if
    
    // Create/overwrite the file
    if comp.File(path) == null then
        touch_result = comp.touch(dir_path, filename)
        if touch_result == null or typeof(touch_result) == "string" then
            return false
        end if
    end if
    
    // Write content
    f = comp.File(path)
    if f == null then return false
    
    f.set_content(content)
    
    // Verify write succeeded
    f = comp.File(path)
    if f == null then return false
    
    written = f.get_content
    if written != content then
        return false  // Content mismatch — write failed
    end if
    
    return true
end function

// Helper: Ensure directory path exists, creating intermediate dirs as needed
ensure_directory_exists = function(dir_path)
    if dir_path == "" or dir_path == "/" then return true
    
    comp = get_shell.host_computer
    current = comp.File(dir_path)
    
    if current != null then
        if current.is_folder then return true
        return false  // Path exists but is not a directory
    end if
    
    // Directory doesn't exist — create it
    // Split path and create each level
    parts = dir_path.split("/")
    current_path = ""
    
    for part in parts
        if part == "" then continue
        
        if current_path == "" then
            current_path = "/" + part
        else
            current_path = current_path + "/" + part
        end if
        
        check = comp.File(current_path)
        if check == null then
            // Directory doesn't exist — create it
            parent_parts = current_path.split("/")
            parent_name = parent_parts.pop
            parent_path = parent_parts.join("/")
            if parent_path == "" then parent_path = "/"
            
            result = comp.create_folder(parent_path, parent_name)
            if typeof(result) == "string" then
                return false  // Error creating directory
            end if
        else if not check.is_folder then
            return false  // Path exists but is a file, not directory
        end if
    end for
    
    return true
end function

// Override the old safe_file_write
safe_file_read = function(path)
    if path == null or path == "" then return null
    
    f = get_shell.host_computer.File(path)
    if f == null then return null
    
    content = f.get_content
    return content
end function

// Network retry wrapper for transient failures
retry_network = function(func, max_attempts, base_delay)
    if max_attempts == null then max_attempts = 3
    if base_delay == null then base_delay = 1
    
    for attempt in range(0, max_attempts - 1)
        result = func()
        if result != null then return result
        
        if attempt < max_attempts - 1 then
            delay = base_delay * (2 ^ attempt)
            if delay > 30 then delay = 30
            wait(delay)
        end if
    end for
    
    return null
end function

// RFC 1918 private IP detection - complete range coverage
is_private_ip = function(ip)
    if ip == null then return false
    if typeof(ip) != "string" then return false
    
    // 192.168.0.0/16
    if ip.indexOf("192.168.") == 0 then return true
    
    // 10.0.0.0/8
    if ip.indexOf("10.") == 0 then return true
    
    // 172.16.0.0/12
    if ip.indexOf("172.") == 0 then
        parts = ip.split(".")
        if parts.len >= 2 then
            second = parts[1].to_int
            if typeof(second) == "number" and second >= 16 and second <= 31 then return true
        end if
    end if
    
    return false
end function
