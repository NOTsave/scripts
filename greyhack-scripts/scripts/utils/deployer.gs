// deployer.gs – deployment and cleanup
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/sanitize_ip.gs")

deployer = {}

deployer.init = function(master_pub_file)
    deployer.master_pub_file = master_pub_file
end function

deployer.deploy_to_target = function(shell, target_ip, current_depth, max_depth, infected_list, infected_file)
    target_safe = sanitize_ip(target_ip)
    log_master("Deploying to " + target_safe, "INFO")
    comp = get_shell.host_computer
    local_tmp = "/tmp/deploy_" + str(time) + "_" + str(get_shell.pid)
    comp.create_folder("/tmp", local_tmp[5:])
    tmp_dir = comp.File(local_tmp)

    files_to_copy = ["/bin/slave.gs", "/bin/worm.gs", "/lib/kyber_lib.gs",
                     "/lib/lib_common.gs", deployer.master_pub_file]
    for src in files_to_copy
        sf = comp.File(src)
        if sf == null then
            log_master("ERROR: Source file not found: " + src, "ERROR")
            tmp_dir.delete
            return false
        end if
        dest_name = src.split("/")[-1]
        copy_result = sf.copy(local_tmp, dest_name)
        if typeof(copy_result) == "string" then  // copy() returns error string on failure
            log_master("ERROR: Failed to copy " + src + ": " + copy_result, "ERROR")
            tmp_dir.delete
            return false
        end if
        // Verify copy succeeded
        copied_file = comp.File(local_tmp + "/" + dest_name)
        if copied_file == null or copied_file.size == 0 then
            log_master("ERROR: Copy verification failed for " + src, "ERROR")
            tmp_dir.delete
            return false
        end if
    end for
    utils = ["/scripts/utils/accessLevel.gs", "/scripts/utils/wipe_logs.gs",
             "/scripts/utils/sanitize_ip.gs", "/scripts/utils/parse_exploit_requirements.gs",
             "/scripts/utils/file_search.gs"]
    for u in utils
        uf = comp.File(u)
        if uf == null then
            log_master("ERROR: Source file not found: " + u, "ERROR")
            tmp_dir.delete
            return false
        end if
        dest_name = u.split("/")[-1]
        copy_result = uf.copy(local_tmp, dest_name)
        if typeof(copy_result) == "string" then  // copy() returns error string on failure
            log_master("ERROR: Failed to copy " + u + ": " + copy_result, "ERROR")
            tmp_dir.delete
            return false
        end if
        // Verify copy succeeded
        copied_file = comp.File(local_tmp + "/" + dest_name)
        if copied_file == null or copied_file.size == 0 then
            log_master("ERROR: Copy verification failed for " + u, "ERROR")
            tmp_dir.delete
            return false
        end if
    end for

    files_list = tmp_dir.get_files
    if files_list then
        for f in files_list
            scp_res = get_shell.scp(local_tmp + "/" + f.name, "/tmp/", shell)
            if typeof(scp_res) == "string" then
                shell.run("rm -f /tmp/*.gs /tmp/master.pub")
                tmp_dir.delete
                return false
            end if
        end for
    end if

    // Safe file operations using GreyScript API instead of shell commands (Item 7)
    source_files = [
        {"src": "/tmp/slave.gs", "dst": "/bin/", "name": "slave.gs"},
        {"src": "/tmp/worm.gs", "dst": "/bin/", "name": "worm.gs"},
        {"src": "/tmp/kyber_lib.gs", "dst": "/lib/", "name": "kyber_lib.gs"},
        {"src": "/tmp/lib_common.gs", "dst": "/lib/", "name": "lib_common.gs"}
    ]
    
    for file_spec in source_files
        src = file_spec.src
        dst_dir = file_spec.dst
        dst_name = file_spec.name
        
        // Verify source exists on target
        src_file = shell.host_computer.File(src)
        if src_file == null then
            log_master("ERROR: Source not found on target: " + src, "ERROR")
            tmp_dir.delete
            return false
        end if
        
        // Fallback: use shell but with explicit quoting
        move_cmd = "mv -- " + char(34) + src + char(34) + " " + char(34) + dst_dir + dst_name + char(34)
        
        result = shell.run(move_cmd)
        if typeof(result) == "string" then
            log_master("ERROR: Failed to move " + src + ": " + result, "ERROR")
            tmp_dir.delete
            return false
        end if
        
        // Verify destination exists
        dst_file = shell.host_computer.File(dst_dir + dst_name)
        if dst_file == null then
            log_master("ERROR: Destination file not found after move: " + dst_dir + dst_name, "ERROR")
            tmp_dir.delete
            return false
        end if
    end for
    
    // Move utility files with proper quoting
    shell.run("mkdir -p /scripts/utils")
    for u in utils
        fn = u.split("/")[-1]
        move_cmd = "mv -- " + char(34) + "/tmp/" + fn + char(34) + " " + char(34) + "/scripts/utils/" + fn + char(34)
        result = shell.run(move_cmd)
        if typeof(result) == "string" then
            log_master("ERROR: Failed to move utility " + fn + ": " + result, "ERROR")
            tmp_dir.delete
            return false
        end if
    end for
    
    // Move master pubkey with proper quoting
    shell.run("mkdir -p /root/.botnet")
    move_cmd = "mv -- " + char(34) + "/tmp/master.pub" + char(34) + " " + char(34) + "/root/.botnet/master.pub" + char(34)
    result = shell.run(move_cmd)
    if typeof(result) == "string" then
        log_master("ERROR: Failed to move master.pub: " + result, "ERROR")
        tmp_dir.delete
        return false
    end if

    shell.launch("/bin/slave.gs")
    if current_depth + 1 < max_depth then
        shell.launch("/bin/worm.gs", [deployer.master_pub_file, str(max_depth), target_ip])
    end if
    infected_list.push(target_ip)
    safe_file_write(infected_file, infected_list.join(char(10)))
    log_master("Deployed to " + target_safe, "SUCCESS")
    tmp_dir.delete
    return true
end function

return deployer
