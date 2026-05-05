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

my_ip = get_shell.host_computer.public_ip
my_ip_safe = sanitize_ip(my_ip)

parent_ip = null
max_depth = 3

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
// ✅ MERGED: Initialize infected list at startup (never null)
infected = []  // Always initialized, never null
infected_data = read_file(infected_file)
if infected_data then
    infected = infected_data.split(char(10))
end if
// infected is now always a list, never null

if infected.indexOf(my_ip) == null then
    infected.push(my_ip)
    write_file(infected_file, infected.join(char(10)))
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
    p = DEPTH_MARKER_DIR + "/" + ip.replace(".", "_")
    safe_file_write(p, str(depth))
    set_permissions(p, "600")
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

// --- Exploit ---
exploit_target = function(ip)
    metax = get_metaxploit()
    if not metax then return null
    ports = [22, 80, 443, 8080, 1542]
    for port in ports
        for attempt in range(0, 2)
            session = metax.net_use(ip, port)
            if typeof(session) == "string" then
                log_master("net_use error: " + session, "DEBUG")
                continue
            end if
            if session == null then continue
            lib = session.dump_lib
            if lib == null then continue
            addrs = metax.scan(lib)
            if typeof(addrs) != "list" then continue
            for addr in addrs
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

// --- Deployment with cleanup on failure ---
deploy_to_target = function(shell, target_ip, current_depth)
    target_safe = sanitize_ip(target_ip)
    log_master("Deploying to " + target_safe, "INFO")
    local_tmp = "/tmp/deploy_" + str(time) + "_" + str(get_shell.pid)
    comp.create_folder("/tmp", local_tmp[5:])
    tmp_dir = comp.File(local_tmp)

    // Copy files locally with verification
    files_to_copy = ["/bin/slave.gs", "/bin/worm.gs", "/lib/kyber_lib.gs",
                     "/lib/lib_common.gs", MASTER_PUB_FILE]
    for src in files_to_copy
        sf = comp.File(src)
        if sf then
            dest_name = src.split("/")[-1]
            src_size = sf.size
            copy_result = sf.copy(local_tmp, dest_name)
            if typeof(copy_result) == "string" then
                log_master("Copy failed: " + src + " - " + copy_result, "ERROR")
                tmp_dir.delete
                return false
            end if
            // Verify copy succeeded
            copied_file = comp.File(local_tmp + "/" + dest_name)
            if copied_file == null then
                log_master("Copy failed: " + src + " (file not found)", "ERROR")
                tmp_dir.delete
                return false
            end if
            if src_size > 0 and copied_file.size == 0 then
                log_master("Copy failed: " + src + " (size mismatch)", "ERROR")
                tmp_dir.delete
                return false
            end if
        else
            log_master("Source file not found: " + src, "ERROR")
            tmp_dir.delete
            return false
        end if
    end for
    utils = ["/scripts/utils/accessLevel.gs", "/scripts/utils/wipe_logs.gs",
             "/scripts/utils/sanitize_ip.gs", "/scripts/utils/parse_exploit_requirements.gs",
             "/scripts/utils/file_search.gs"]
    for u in utils
        uf = comp.File(u)
        if uf then
            dest_name = u.split("/")[-1]
            src_size = uf.size
            copy_result = uf.copy(local_tmp, dest_name)
            if typeof(copy_result) == "string" then
                log_master("Copy failed: " + u + " - " + copy_result, "ERROR")
                tmp_dir.delete
                return false
            end if
            // Verify copy succeeded
            copied_file = comp.File(local_tmp + "/" + dest_name)
            if copied_file == null then
                log_master("Copy failed: " + u + " (file not found)", "ERROR")
                tmp_dir.delete
                return false
            end if
            if src_size > 0 and copied_file.size == 0 then
                log_master("Copy failed: " + u + " (size mismatch)", "ERROR")
                tmp_dir.delete
                return false
            end if
        else
            log_master("Utility file not found: " + u, "ERROR")
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
                // Cleanup remote temp
                shell.run("rm -f /tmp/slave.gs /tmp/worm.gs /tmp/kyber_lib.gs /tmp/lib_common.gs /tmp/master.pub /tmp/accessLevel.gs /tmp/wipe_logs.gs /tmp/sanitize_ip.gs /tmp/parse_exploit_requirements.gs /tmp/file_search.gs")
                tmp_dir.delete
                return false
            end if
        end for
    end if

    // Move files on target
    shell.run("mv /tmp/slave.gs /bin/slave.gs")
    shell.run("mv /tmp/worm.gs /bin/worm.gs")
    shell.run("mv /tmp/kyber_lib.gs /lib/kyber_lib.gs")
    shell.run("mv /tmp/lib_common.gs /lib/lib_common.gs")
    shell.run("mkdir -p /scripts/utils")
    for u in utils
        fn = u.split("/")[-1]
        shell.run("mv /tmp/" + fn + " /scripts/utils/" + fn)
    end for
    shell.run("mkdir -p /root/.botnet")
    shell.run("mv /tmp/master.pub /root/.botnet/master.pub")

    shell.launch("/bin/slave.gs")

    if current_depth + 1 < max_depth then
        // Deliberately omit 4th parameter
        shell.launch("/bin/worm.gs", [MASTER_PUB_FILE, str(max_depth), target_ip])
    end if

    infected.push(target_ip)
    write_file(infected_file, infected.join(char(10)))
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
