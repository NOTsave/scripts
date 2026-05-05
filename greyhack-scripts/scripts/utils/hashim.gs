// hashim.gs - Asynchronous hash cracking daemon
// Ported from 5hell's hashim daemon concept
// Listens for hash cracking jobs and processes them using pre-computed tables
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/pwgen.gs")

// Configuration
HASHIM_QUEUE = "/root/.botnet/hashim_queue.txt"
HASHIM_RESULTS = "/root/.botnet/hashim_results.txt"
HASHIM_STATUS = "/root/.botnet/hashim_status.txt"
HASHIM_PID = "/root/.botnet/hashim.pid"
MAX_QUEUE_SIZE = 100
CHECK_INTERVAL = 5  // seconds

hashim = {}

hashim.running = false
hashim.total_processed = 0
hashim.successful_cracks = 0
hashim.start_time = 0
hashim._initialized = false

// Initialize hashim daemon
hashim.init = function()
    // Check if already running
    if get_shell.host_computer.File(HASHIM_PID) != null then
        log_master("Hashim daemon already running", "WARN")
        return false
    end if
    
    // Write PID file
    current_pids = get_pids("hashim.gs")
    if current_pids.len > 1 then
        print("Hashim already running, PID: " + str(current_pids[0]))
        return false
    end if
    // len is 0 or 1 - write current PID either way
    if current_pids.len == 1 then
        write_file(HASHIM_PID, str(current_pids[0]))
    else
        write_file(HASHIM_PID, str(get_shell.pid))
    end if
    
    // Initialize queue and results files
    if not get_shell.host_computer.File(HASHIM_QUEUE) then
        write_file(HASHIM_QUEUE, "")
    end if
    if not get_shell.host_computer.File(HASHIM_RESULTS) then
        write_file(HASHIM_RESULTS, "")
    end if
    
    hashim.running = true
    hashim._initialized = true
    hashim.start_time = time
    log_master("Hashim daemon initialized", "SUCCESS")
    return true
end function

// Add hash to cracking queue
hashim.queue_hash = function(username, hash, priority=0)
    entry = username + ":" + hash + ":" + str(priority) + ":" + str(time)
    
    // Read current queue
    queue_content = read_file(HASHIM_QUEUE)
    if queue_content == null then queue_content = ""
    
    lines = queue_content.split(char(10))
    if lines.len >= MAX_QUEUE_SIZE then
        log_master("Hashim queue full, dropping oldest entry", "WARN")
        lines = lines[1:]  // Remove oldest
    end if
    
    // Insert based on priority (higher priority first)
    inserted = false
    for i in range(0, lines.len - 1)
        if lines[i] == "" then continue
        parts = lines[i].split(":")
        if parts.len >= 3 and parts[2].to_int < priority then
            lines.insert(i, entry)
            inserted = true
            break
        end if
    end for
    
    if not inserted then
        lines.push(entry)
    end if
    
    write_file(HASHIM_QUEUE, lines.join(char(10)))
    log_master("Queued hash for " + username, "INFO")
end function

// Process single hash against tables
hashim.crack_hash = function(username, target_hash)
    log_master("Cracking hash for " + username, "DEBUG")
    
    // Load available hash tables
    comp = get_shell.host_computer
    t5_dir = comp.File("/data/t5")
    if not t5_dir then
        log_master("No hash tables found", "WARN")
        return null
    end if
    
    table_files = t5_dir.get_files
    if table_files == null then return null
    
    // Check each table
    for table_file in table_files
        if not table_file.name.startswith("table_") or not table_file.name.endswith(".txt") then
            continue
        end if
        
        table_content = read_file("/data/t5/" + table_file.name)
        if table_content == null then continue
        
        lines = table_content.split(char(10))
        for line in lines
            if line == "" then continue
            parts = line.split(":")
            if parts.len == 2 and parts[1] == target_hash then
                password = parts[0]
                log_master("Cracked " + username + " password: " + password, "SUCCESS")
                hashim.successful_cracks = hashim.successful_cracks + 1
                return password
            end if
        end for
    end for
    
    return null
end function

// Main daemon loop
hashim.run = function()
    hashim.init()
    if not hashim._initialized then
        log_master("Failed to initialize hashim daemon", "ERROR")
        return
    end if
    
    log_master("Hashim daemon started", "INFO")
    
    while hashim.running
        // Check queue
        queue_content = read_file(HASHIM_QUEUE)
        if queue_content == null or queue_content.trim == "" then
            wait(CHECK_INTERVAL)
            continue
        end if
        
        lines = queue_content.split(char(10))
        if lines.len == 0 then
            wait(CHECK_INTERVAL)
            continue
        end if
        
        // Process first entry
        entry = lines[0]
        if entry == "" then
            // Remove empty line and continue
            lines = lines[1:]
            write_file(HASHIM_QUEUE, lines.join(char(10)))
            wait(CHECK_INTERVAL)
            continue
        end if
        
        parts = entry.split(":")
        if parts.len < 4 then
            // Invalid entry, remove it
            lines = lines[1:]
            write_file(HASHIM_QUEUE, lines.join(char(10)))
            continue
        end if
        
        username = parts[0]
        target_hash = parts[1]
        priority = parts[2]
        timestamp = parts[3]
        
        // Attempt to crack
        password = hashim.crack_hash(username, target_hash)
        
        // Store result
        if password != null then
            password_str = password
        else
            password_str = "FAILED"
        end if
        result_entry = username + ":" + target_hash + ":" + password_str + ":" + str(time)
        results_content = read_file(HASHIM_RESULTS)
        if results_content == null then results_content = ""
        results_content = results_content + result_entry + char(10)
        write_file(HASHIM_RESULTS, results_content)
        
        // Remove from queue
        lines = lines[1:]
        write_file(HASHIM_QUEUE, lines.join(char(10)))
        
        hashim.total_processed = hashim.total_processed + 1
        
        // Update status
        status = "running:" + str(hashim.total_processed) + ":" + str(hashim.successful_cracks) + ":" + str(time - hashim.start_time)
        write_file(HASHIM_STATUS, status)
        
        wait(1)  // Small delay between processing
    end while
    
    // Cleanup
    if get_shell.host_computer.File(HASHIM_PID) != null then
        get_shell.host_computer.File(HASHIM_PID).delete
    end if
    
    log_master("Hashim daemon stopped", "INFO")
end function

// Stop the daemon
hashim.stop = function()
    hashim.running = false
    log_master("Stopping hashim daemon...", "INFO")
end function

// Get daemon status
hashim.get_status = function()
    status_content = read_file(HASHIM_STATUS)
    if status_content == null then
        return "stopped"
    end if
    
    parts = status_content.split(":")
    if parts.len < 4 then
        return "unknown"
    end if
    
    return {
        "state": parts[0],
        "processed": parts[1].to_int,
        "cracked": parts[2].to_int,
        "runtime": parts[3].to_int
    }
end function

// Get results for a specific user
hashim.get_result = function(username)
    results_content = read_file(HASHIM_RESULTS)
    if results_content == null then return null
    
    lines = results_content.split(char(10))
    for line in lines
        if line == "" then continue
        parts = line.split(":")
        if parts.len >= 3 and parts[0] == username then
            if parts[2] != "FAILED" then
                return parts[2]  // Return password
            end if
        end if
    end for
    
    return null
end function

// Queue hashes from /etc/passwd file
hashim.queue_passwd_file = function(shell=null)
    if shell == null then shell = get_shell
    
    passwd_file = shell.host_computer.File("/etc/passwd")
    if not passwd_file then
        log_master("No /etc/passwd file found", "WARN")
        return false
    end if
    
    passwd_content = passwd_file.get_content
    if passwd_content == null then return false
    
    lines = passwd_content.split(char(10))
    queued_count = 0
    
    for line in lines
        if line == "" then continue
        parts = line.split(":")
        if parts.len < 2 then continue
        
        username = parts[0]
        password_hash = parts[1]
        
        // Skip empty hashes and system accounts
        if password_hash == "" or password_hash == "*" or password_hash == "!" then
            continue
        end if
        
        // Skip if already processed
        if hashim.get_result(username) != null then
            continue
        end if
        
        hashim.queue_hash(username, password_hash, 1)
        queued_count = queued_count + 1
    end for
    
    log_master("Queued " + queued_count + " hashes from /etc/passwd", "INFO")
    return queued_count > 0
end function

// Auto-start if run as daemon
if len(params) > 0 and params[0] == "daemon" then
    hashim.run
else if len(params) > 0 and params[0] == "stop" then
    hashim.stop
else if len(params) > 0 and params[0] == "status" then
    status = hashim.get_status
    if typeof(status) == "map" then
        print("Hashim Status: " + status["state"])
        print("Processed: " + status["processed"])
        print("Cracked: " + status["cracked"])
        print("Runtime: " + status["runtime"] + " seconds")
    else
        print("Hashim Status: " + status)
    end if
else if len(params) > 0 and params[0] == "queue" and params.len >= 3 then
    if params.len >= 4 then
        priority = params[3].to_int
    else
        priority = 0
    end if
    hashim.queue_hash(params[1], params[2], priority)
else
    print("Usage: hashim [command] [options]")
    print("Commands:")
    print("  daemon       - Start the daemon")
    print("  stop         - Stop the daemon")
    print("  status       - Show daemon status")
    print("  queue <user> <hash> [priority] - Queue a hash for cracking")
    print("  queue_passwd - Queue hashes from /etc/passwd")
end if
