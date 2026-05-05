// persistence.gs - Anti-forensics and persistence mechanisms
// Consolidated forensics tools

import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")

// ============================================
// Persistence Configuration
// ============================================

PERSISTENCE_LOCATIONS = [
    "/etc/cron.d/botnet",
    "/etc/init.d/botnet", 
    "/root/.bashrc",
    "/home/guest/.bashrc"
]

WATCHDOG_INTERVAL = 300  // 5 minutes

// ============================================
// Log Management
// ============================================

wipe_logs = function(aggressive=false)
    comp = get_shell.host_computer
    
    // Standard log locations
    log_files = [
        "/var/log/auth.log",
        "/var/log/syslog", 
        "/var/log/messages",
        "/root/.bash_history",
        "/home/guest/.bash_history"
    ]
    
    if aggressive then
        log_files = log_files + [
            "/var/log/secure",
            "/var/log/kern.log",
            "/var/log/daemon.log",
            "/var/log/user.log"
        ]
    end if
    
    wiped = 0
    for log_path in log_files
        log_file = comp.File(log_path)
        if log_file != null then
            log_file.set_content("")
            wiped = wiped + 1
        end if
    end for
    
    // Clear shell history
    get_shell.run("history -c")
    
    log_master("Wiped " + str(wiped) + " log files", "INFO")
    return wiped
end function

rotate_logs = function(max_size_mb=10)
    comp = get_shell.host_computer
    
    // Rotate botnet logs
    logs = ["/root/.botnet/log.txt", "/root/.botnet/infections.txt"]
    
    for log_path in logs
        f = comp.File(log_path)
        if f != null and f.size > (max_size_mb * 1024 * 1024) then
            backup = log_path + ".1"
            f.copy(backup[0:backup.len-2], backup.split("/")[-1])
            f.set_content("")
            log_master("Rotated log: " + log_path, "INFO")
        end if
    end for
end function

// ============================================
// Process Monitoring
// ============================================

get_suspicious_processes = function()
    comp = get_shell.host_computer
    procs = comp.show_procs
    
    if procs == null then return []
    
    suspicious = []
    for proc in procs
        if proc == null then continue
        
        // Look for competing tools
        name = proc.name or ""
        if name.indexOf("metaxploit") != null or
           name.indexOf("hack") != null or
           name.indexOf("exploit") != null or
           name.indexOf("brute") != null then
            suspicious.push(proc)
        end if
    end for
    
    return suspicious
end function

kill_suspicious_processes = function()
    suspicious = get_suspicious_processes()
    killed = 0
    
    for proc in suspicious
        if proc.pid != null then
            comp.close_program(proc.pid)
            killed = killed + 1
            log_master("Killed suspicious process: " + (proc.name or "unknown"), "INFO")
        end if
    end for
    
    return killed
end function

// ============================================
// File Integrity Monitoring
// ============================================

calculate_file_hash = function(file_path)
    f = get_shell.host_computer.File(file_path)
    if f == null then return null
    
    content = f.get_content
    if content == null then return null
    
    // Simple hash for GreyScript
    hash = 0
    for i in range(0, content.len - 1)
        hash = (hash * 31 + content[i].code) % 2147483647
    end for
    
    return str(hash)
end function

monitor_critical_files = function()
    critical_files = [
        "/bin/slave.gs",
        "/bin/worm.gs", 
        "/lib/kyber_lib.gs",
        "/lib/lib_common.gs"
    ]
    
    comp = get_shell.host_computer
    changes = []
    
    for file_path in critical_files
        f = comp.File(file_path)
        if f == null then continue
        
        current_hash = calculate_file_hash(file_path)
        stored_hash = globals.file_hashes
        
        if stored_hash == null then
            globals.file_hashes = {}
        end if
        
        if globals.file_hashes.hasIndex(file_path) then
            if globals.file_hashes[file_path] != current_hash then
                changes.push(file_path)
                log_master("File tampering detected: " + file_path, "WARN")
            end if
        end if
        
        globals.file_hashes[file_path] = current_hash
    end for
    
    return changes
end function

// ============================================
// Persistence Mechanisms
// ============================================

install_persistence = function()
    comp = get_shell.host_computer
    installed = 0
    
    // Add cron job
    cron_content = "*/5 * * * * /bin/slave.gs > /dev/null 2>&1"
    if safe_file_write("/etc/cron.d/botnet", cron_content) then
        installed = installed + 1
    end if
    
    // Add to bashrc
    bashrc_content = "/bin/slave.gs &"
    for bashrc in ["/root/.bashrc", "/home/guest/.bashrc"]
        existing = safe_file_read(bashrc)
        if existing != null and existing.indexOf(bashrc_content) == null then
            new_content = existing + char(10) + bashrc_content
            safe_file_write(bashrc, new_content)
            installed = installed + 1
        end if
    end for
    
    log_master("Installed persistence on " + str(installed) + " locations", "INFO")
    return installed
end function

remove_persistence = function()
    comp = get_shell.host_computer
    removed = 0
    
    // Remove cron job
    cron_file = comp.File("/etc/cron.d/botnet")
    if cron_file != null then
        cron_file.delete
        removed = removed + 1
    end if
    
    // Remove from bashrc
    bashrc_content = "/bin/slave.gs &"
    for bashrc in ["/root/.bashrc", "/home/guest/.bashrc"]
        content = safe_file_read(bashrc)
        if content != null then
            lines = content.split(char(10))
            filtered = []
            for line in lines
                if line.indexOf(bashrc_content) == null then
                    filtered.push(line)
                end if
            end for
            safe_file_write(bashrc, filtered.join(char(10)))
            removed = removed + 1
        end if
    end for
    
    log_master("Removed persistence from " + str(removed) + " locations", "INFO")
    return removed
end function

// ============================================
// Watchdog Service
// ============================================

watchdog_loop = function()
    log_master("Starting anti-forensics watchdog", "INFO")
    
    while true
        // Kill suspicious processes
        killed = kill_suspicious_processes()
        if killed > 0 then
            log_master("Watchdog killed " + str(killed) + " suspicious processes", "INFO")
        end if
        
        // Monitor file integrity
        changes = monitor_critical_files()
        if changes.len > 0 then
            log_master("Watchdog detected " + str(changes.len) + " file changes", "WARN")
        end if
        
        // Rotate logs if needed
        rotate_logs()
        
        // Periodic log wipe (light)
        if time % 3600 < WATCHDOG_INTERVAL then  // Once per hour
            wipe_logs(false)
        end if
        
        wait(WATCHDOG_INTERVAL)
    end while
end function

start_watchdog = function()
    // Run watchdog in background
    get_shell.launch("/bin/watchdog.gs")
    log_master("Started anti-forensics watchdog service", "INFO")
end function

// ============================================
// Clean-up Utilities
// ============================================

secure_delete = function(file_path)
    comp = get_shell.host_computer
    f = comp.File(file_path)
    
    if f != null then
        // Overwrite with random data
        size = f.size
        for i in range(0, 2)  // 3 passes
            random_data = ""
            for j in range(0, size - 1)
                random_data = random_data + char(floor(rnd * 256))
            end for
            f.set_content(random_data)
        end for
        
        // Delete file
        f.delete
        log_master("Securely deleted: " + file_path, "INFO")
        return true
    end if
    
    return false
end function

cleanup_temp_files = function()
    comp = get_shell.host_computer
    tmp_dir = comp.File("/tmp")
    
    if tmp_dir == null then return 0
    
    cleaned = 0
    files = tmp_dir.get_files
    
    if files != null then
        for f in files
            if f == null then continue
            
            // Clean botnet-related temp files
            if f.name.indexOf("deploy_") == 0 or
               f.name.indexOf("c2_") == 0 or
               f.name.indexOf("cmd_") == 0 then
                secure_delete("/tmp/" + f.name)
                cleaned = cleaned + 1
            end if
        end for
    end if
    
    log_master("Cleaned " + str(cleaned) + " temporary files", "INFO")
    return cleaned
end function
