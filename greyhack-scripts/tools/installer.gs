// installer.gs - Deploy botnet to a target (requires root shell)
if params.len < 2 then exit("Usage: installer.gs <target_ip> <root_password>")
target_ip = params[0]
root_pass = params[1]

shell = get_shell.connect_service(target_ip, 22, "root", root_pass)
if not shell then exit("Cannot connect to target")

// Upload files
files = ["/bin/slave.gs", "/bin/worm.gs", "/lib/kyber_lib.gs", "/lib/lib_common.gs", "/root/.botnet/master.pub"]
for f in files
    get_shell.scp(f, "/root/.botnet/", shell)
end for

shell.run("mkdir -p /root/.botnet/commands /root/.botnet/responses")
shell.run("chmod +x /bin/slave.gs /bin/worm.gs")
shell.launch("/bin/slave.gs")
print("Botnet deployed to " + target_ip)
