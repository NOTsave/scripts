// ======================================
// worm.gs
// Self-propagating agent: exploits LAN,
// deploys payload, manages depth
// Dependencies: kyber_lib.gs, lib_common.gs
// ======================================
// Depth is purely calculated from parent markers; 4th parameter ignored.
import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/accessLevel.gs")
import_code("/scripts/utils/parse_exploit_requirements.gs")
import_code("/scripts/utils/sanitize_ip.gs")
import_code("/scripts/utils/find_lib.gs")
import_code("/scripts/utils/botnet_config.gs")

// Use centralized configuration
MASTER_PUB_FILE = get_master_pub_file()
DEPTH_MARKER_DIR = get_depth_markers_dir()
HARD_DEPTH_CAP = get_hard_depth_cap()
SPREAD_DELAY = get_spread_delay()

// Rate limiting configuration - use centralized config
MAX_ATTEMPTS_PER_CYCLE = get_config("worm.max_attempts_per_cycle") or 5
CYCLE_COOLDOWN = get_config("worm.cycle_cooldown") or 60
CONNECTION_TIMEOUT = get_config("worm.connection_timeout") or 10

my_ip = get_shell.host_computer.public_ip
my_ip_safe = sanitize_ip(my_ip)

parent_ip = null
max_depth = 3

// Rate limiting state
cycle_attempts = 0
cycle_start_time = time

// Parse parameters
if params.len < 4 then
    // Standalone launch: use defaults
    if params.len >= 1 then
        MASTER_PUB_FILE = params[0]
    else
        MASTER_PUB_FILE = get_master_pub_file()
    end if
    if params.len >= 2 then
        max_depth = params[1].to_int
    else
        max_depth = get_default_max_depth()
    end if
    if params.len >= 3 then
        parent_ip = params[2]
    else
        parent_ip = null
    end if
    if params.len >= 4 then
        current_depth = params[3].to_int
    else
        current_depth = 0
    end if
else
    MASTER_PUB_FILE = params[0]
    max_depth = params[1].to_int
    parent_ip = params[2]
    current_depth = params[3].to_int
end if

master_pub = read_file(MASTER_PUB_FILE)
if not master_pub then exit("Master public key not found")

infected_file = get_infected_file()

// ============================================
// Lock management for infected file (Item 5)
// ============================================

lock_infected = function()
    comp = get_shell.host_computer
    lock_path = "/root/.botnet/infected.lock"
    for attempt in range(0, 29)  // 30 attempts, ~30-60 seconds total
        // Atomic: touch + verify in one step
        lock_file = comp.File(lock_path)
        if lock_file == null then
            // File doesn't exist; try to create it
            if comp.touch("/root/.botnet", "infected.lock") != null then
                // Verify we got the lock (file exists and we own it)
                lock_file = comp.File(lock_path)
                if lock_file != null then
                    return true  // Successfully acquired lock atomically
                end if
            end if
        end if
        // Exponential backoff: 1s, 2s, 4s, 8s, etc.
        backoff = 2 ^ (attempt % 5)
        wait(backoff + floor(rnd * 2))
    end for
    log_master("WARNING: Could not acquire infected-list lock after 30 attempts", "WARN")
    return false
end function

unlock_infected = function()
    comp = get_shell.host_computer
    lock_file = comp.File("/root/.botnet/infected.lock")
    if lock_file != null then
        lock_file.delete
    end if
end function

// Single source of truth for infected list
populate_infected_list = function()
    infected_data = read_file(infected_file)
    infected = []
    if infected_data then
        lines = infected_data.split(char(10))
        for line in lines
            if line and line.len > 0 then
                infected.push(line)
            end if
        end for
    end if
    return infected
end function

// Initialize infected list
infected = populate_infected_list()
if infected.indexOf(my_ip) == null then
    if lock_infected() then
        infected.push(my_ip)
        new_content = infected.join(char(10))
        if write_file(infected_file, new_content) then
            log_master("Registered infection on " + my_ip_safe, "INFO")
        else
            log_master("ERROR: Failed to register infection", "ERROR")
        end if
        unlock_infected()
    else
        log_master("Could not acquire lock; proceeding with in-memory list", "WARN")
    end if
end if

log_master("Worm started on " + my_ip_safe, "INFO")

comp = get_shell.host_computer
if not comp.File(DEPTH_MARKER_DIR) then
    comp.create_folder("/root/.botnet", "depth_markers")
end if

// ✅ MERGED: TTL-based router cache initialization
globals.my_router = null
globals.router_cache_time = 0
globals.router_cache_ttl = 300  // 5 minutes

calculate_current_depth = function()
    if parent_ip == null then return 0
    
    // Validate parent_ip
    if not is_valid_ip(parent_ip) then
        log_master("WARNING: Invalid parent_ip: " + parent_ip, "WARN")
        return 0
    end if
    
    marker_path = DEPTH_MARKER_DIR + "/" + parent_ip.replace(".", "_")
    mf = comp.File(marker_path)
    if mf != null then
        sd = mf.get_content
        if sd != null then
            d = sd.to_int
            if typeof(d) == "number" then return d + 1
        end if
    end if
    return 1
end function

store_depth_marker = function(ip, depth)
    if ip == null or depth == null then return false
    
    // Get master public key to encrypt marker (Item 14)
    master_pub = read_file(MASTER_PUB_FILE)
    if not master_pub then
        // FAIL SECURELY: Do not write unencrypted markers
        log_master("ERROR: Cannot encrypt depth marker (master pubkey missing), stopping propagation", "ERROR")
        return false
    end if
    
    // Encrypt depth value with master's public key
    // Only master can decrypt and verify this
    depth_json = "{" + char(34) + "ip" + char(34) + ":" + char(34) + ip + char(34) + 
                 "," + char(34) + "depth" + char(34) + ":" + str(depth) + 
                 "," + char(34) + "timestamp" + char(34) + ":" + str(time) + "}"
    
    cipher = Kyber.encrypt_message(master_pub, depth_json)
    if cipher == null then
        log_master("ERROR: Failed to encrypt depth marker for " + sanitize_ip(ip), "ERROR")
        return false
    end if
    
    // Write encrypted marker
    marker_name = ip.replace(".", "_") + ".enc"
    p = DEPTH_MARKER_DIR + "/" + marker_name
    
    if safe_file_write(p, cipher) then
        set_permissions(p, "600")
        return true
    else
        log_master("ERROR: Failed to write encrypted depth marker", "ERROR")
        return false
    end if
end function

verify_depth_marker = function(ip, expected_depth)
    // Only callable by master (has private key)
    master_priv = read_file(get_master_priv_file())
    if not master_priv then return false
    
    marker_name = ip.replace(".", "_") + ".enc"
    p = DEPTH_MARKER_DIR + "/" + marker_name
    
    cipher = read_file(p)
    if not cipher then return false
    
    // Decrypt with master's private key
    json_str = Kyber.decrypt_message(master_priv, cipher)
    if not json_str then return false
    
    // Parse JSON (simple)
    depth_idx = json_str.indexOf(char(34) + "depth" + char(34))
    if depth_idx == null then return false
    
    // Extract depth value
    // This is fragile JSON parsing; for production use a proper parser
    colon_idx = json_str.indexOf(":", depth_idx)
    comma_idx = json_str.indexOf(",", colon_idx)
    if comma_idx == null then comma_idx = json_str.indexOf("}", colon_idx)
    
    depth_str = json_str[colon_idx + 1 : comma_idx].trim
    depth = depth_str.to_int
    
    return depth == expected_depth
end function

current_depth = calculate_current_depth()

if current_depth >= HARD_DEPTH_CAP then
    store_depth_marker(my_ip, HARD_DEPTH_CAP)
    log_master("Hard depth cap reached, dormant", "WARN")
    while true; wait(300); end while
end if

if current_depth >= max_depth then
    store_depth_marker(my_ip, current_depth)
    log_master("Max depth reached, idle", "INFO")
    while true; wait(60); end while
end if

store_depth_marker(my_ip, current_depth)

// --- LAN scanning with TTL-based cache ---
scan_lan = function()
    current_time = time
    
    // ✅ TTL-based automatic invalidation
    if globals.my_router != null then
        cache_age = current_time - globals.router_cache_time
        if cache_age >= globals.router_cache_ttl then
            log_master("Router cache expired (age: " + cache_age + "s), refreshing", "DEBUG")
            globals.my_router = null
        end if
    end if
    
    // Get fresh router if not cached
    if globals.my_router == null then
        globals.my_router = get_router(my_ip)
        globals.router_cache_time = current_time
        if globals.my_router == null then
            globals.my_router = get_router(get_shell.host_computer.lan_ip)
            if globals.my_router == null then
                log_master("Could not get router for both IPs", "WARN")
                return []
            end if
        end if
    end if
    
    router = globals.my_router
    if router == null then return []
    targets = []
    for ip in router.computers_lan_ip
        if ip == my_ip then continue
        if infected.indexOf(ip) != null then continue
        if parent_ip != null and ip == parent_ip then continue
        if not is_private_ip(ip) then continue
        targets.push(ip)
    end for
    return targets
end function

// --- Rate limiting check ---
check_rate_limit = function()
    current_time = time
    
    // Reset cycle if enough time has passed
    if current_time - cycle_start_time >= CYCLE_COOLDOWN then
        cycle_attempts = 0
        cycle_start_time = current_time
        return false  // Not rate limited
    end if
    
    // Check if we've exceeded the max attempts per cycle
    if cycle_attempts >= MAX_ATTEMPTS_PER_CYCLE then
        wait_time = CYCLE_COOLDOWN - (current_time - cycle_start_time)
        log_master("Rate limit reached, waiting " + str(wait_time) + "s", "WARN")
        wait(wait_time)
        cycle_attempts = 0
        cycle_start_time = time
        return true  // Was rate limited
    end if
    
    return false  // Not rate limited
end function

// --- Exploit with timeout checks ---
exploit_target = function(ip)
    // Check rate limiting before attempting exploit
    if check_rate_limit() then
        return null  // Skip due to rate limiting
    end if
    
    cycle_attempts = cycle_attempts + 1
    metax = get_metaxploit()
    if not metax then return null
    ports = [22, 80, 443, 8080, 1542]
    start_time = time  // Track start time
    
    for port in ports
        for attempt in range(0, 2)
            // Timeout check
            if time - start_time > CONNECTION_TIMEOUT then
                log_master("Timeout on " + sanitize_ip(ip) + ":" + str(port), "WARN")
                return null
            end if
            
            session = metax.net_use(ip, port)
            if typeof(session) == "string" then
                log_master("net_use error: " + session, "DEBUG")
                continue
            end if
            if session == null then continue
            
            // Timeout check
            if time - start_time > CONNECTION_TIMEOUT then
                log_master("Timeout during scan for " + sanitize_ip(ip), "WARN")
                return null
            end if
            
            lib = session.dump_lib
            if lib == null then continue
            
            addrs = metax.scan(lib)
            if typeof(addrs) != "list" then continue
            
            for addr in addrs
                // Timeout check
                if time - start_time > CONNECTION_TIMEOUT then
                    log_master("Timeout during address scan for " + sanitize_ip(ip), "WARN")
                    return null
                end if
                
                raw = metax.scan_address(lib, addr)
                if typeof(raw) != "string" then continue
                reqs = parse_exploit_requirements(raw)
                if typeof(reqs) == "map" and reqs.hasIndex("activeRoot") then
                    shell = lib.overflow(addr, reqs["activeRoot"], "")
                    if shell != null then
                        if accessLevel(shell) == "root" then return shell
                    end if
                end if
            end for
            backoff_sleep(attempt, 1, 5)
        end for
    end for
    return null
end function

// --- Deployment with proper rollback on failure ---
deploy_to_target = function(shell, target_ip, current_depth)
    target_safe = sanitize_ip(target_ip)
    log_master("Deploying to " + target_safe, "INFO")
    comp = get_shell.host_computer
    local_tmp = "/tmp/deploy_" + str(time) + "_" + str(get_shell.pid)
    comp.create_folder("/tmp", local_tmp[5:])
    tmp_dir = comp.File(local_tmp)

    // Track all files for rollback
    files_to_copy = ["/bin/slave.gs", "/bin/worm.gs", "/lib/kyber_lib.gs",
                     "/lib/lib_common.gs", MASTER_PUB_FILE]
    utils = ["/scripts/utils/accessLevel.gs", "/scripts/utils/wipe_logs.gs",
             "/scripts/utils/sanitize_ip.gs", "/scripts/utils/parse_exploit_requirements.gs",
             "/scripts/utils/file_search.gs"]
    all_files = files_to_copy + utils
    copied_to_target = []  // Track for rollback

    // Copy files locally
    for src in all_files
        sf = comp.File(src)
        if sf == null then
            log_master("Source file not found: " + src, "ERROR")
            tmp_dir.delete
            return false
        end if
        dest_name = src.split("/")[-1]
        if sf.copy(local_tmp, dest_name) == null then
            log_master("Copy failed: " + src, "ERROR")
            tmp_dir.delete
            return false
        end if
    end for

    // SCP to target
    files_list = tmp_dir.get_files
    if files_list then
        for f in files_list
            result = get_shell.scp(local_tmp + "/" + f.name, "/tmp/", shell)
            if typeof(result) == "string" then
                log_master("SCP failed: " + result, "ERROR")
                // Rollback: Clean up ALL copied files
                for copied_file in copied_to_target
                    shell.run("rm -f " + char(34) + "/tmp/" + copied_file + char(34))
                end for
                tmp_dir.delete
                return false
            end if
            copied_to_target.push(f.name)  // Track for rollback
        end for
    end if

    // Move files on target (with rollback on failure)
    move_commands = [
        {"cmd": "mv -- " + char(34) + "/tmp/slave.gs" + char(34) + " " + char(34) + "/bin/slave.gs" + char(34), "file": "slave.gs"},
        {"cmd": "mv -- " + char(34) + "/tmp/worm.gs" + char(34) + " " + char(34) + "/bin/worm.gs" + char(34), "file": "worm.gs"},
        {"cmd": "mv -- " + char(34) + "/tmp/kyber_lib.gs" + char(34) + " " + char(34) + "/lib/kyber_lib.gs" + char(34), "file": "kyber_lib.gs"},
        {"cmd": "mv -- " + char(34) + "/tmp/lib_common.gs" + char(34) + " " + char(34) + "/lib/lib_common.gs" + char(34), "file": "lib_common.gs"},
        {"cmd": "mkdir -p " + char(34) + "/scripts/utils" + char(34), "file": null}
    ]
    for u in utils
        fn = u.split("/")[-1]
        move_commands.push({
            "cmd": "mv -- " + char(34) + "/tmp/" + fn + char(34) + " " + char(34) + "/scripts/utils/" + fn + char(34),
            "file": fn
        })
    end for
    move_commands.push({
        "cmd": "mkdir -p " + char(34) + "/root/.botnet" + char(34),
        "file": null
    })
    move_commands.push({
        "cmd": "mv -- " + char(34) + "/tmp/master.pub" + char(34) + " " + char(34) + "/root/.botnet/master.pub" + char(34),
        "file": "master.pub"
    })

    for move_cmd in move_commands
        result = shell.run(move_cmd.cmd)
        if typeof(result) == "string" and result != "" then
            log_master("Move failed: " + move_cmd.cmd + " - " + result, "ERROR")
            // Rollback: Clean up ALL moved files
            for copied_file in copied_to_target
                shell.run("rm -f " + char(34) + "/tmp/" + copied_file + char(34) +
                          " " + char(34) + "/bin/" + copied_file + char(34) +
                          " " + char(34) + "/lib/" + copied_file + char(34) +
                          " " + char(34) + "/scripts/utils/" + copied_file + char(34) +
                          " " + char(34) + "/root/.botnet/" + copied_file + char(34))
            end for
            tmp_dir.delete
            return false
        end if
    end for

    shell.launch("/bin/slave.gs")

    if current_depth + 1 < max_depth then
        // Deliberately omit 4th parameter
        shell.launch("/bin/worm.gs", [MASTER_PUB_FILE, str(max_depth), target_ip])
    end if

    infected.push(target_ip)
    // Use lock when updating infected list
    if lock_infected() then
        new_content = infected.join(char(10))
        if write_file(infected_file, new_content) then
            log_master("Updated infected list for " + target_safe, "DEBUG")
        else
            log_master("ERROR: Failed to update infected list", "ERROR")
        end if
        unlock_infected()
    else
        log_master("WARNING: Could not lock infected list during update", "WARN")
    end if
    log_master("Deployed to " + target_safe, "SUCCESS")
    tmp_dir.delete
    return true
end function

// --- Main loop ---
main = function()
    consecutive_failures = 0
    while true
        targets = scan_lan()
        if targets.len == 0 then
            consecutive_failures = consecutive_failures + 1
            if consecutive_failures > 5 then
                log_master("No targets, sleeping 5min", "WARN")
                wait(300)
                consecutive_failures = 0
            end if
        else
            consecutive_failures = 0
        end if
        for target in targets
            log_master("Attempting " + sanitize_ip(target), "INFO")
            shell = exploit_target(target)
            if shell then
                deploy_to_target(shell, target, current_depth)
            else
                log_master("Failed " + sanitize_ip(target), "WARN")
            end if
        end for
        wait(SPREAD_DELAY)
    end while
end function

main()
