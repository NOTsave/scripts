// worm.gs – coordinator using scanner, exploiter, deployer
import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/sanitize_ip.gs")
import_code("/scripts/utils/scanner.gs")
import_code("/scripts/utils/exploiter.gs")
import_code("/scripts/utils/deployer.gs")

MASTER_PUB_FILE = "/root/.botnet/master.pub"
HARD_DEPTH_CAP = 5
SPREAD_DELAY = 30

my_ip = get_shell.host_computer.public_ip
parent_ip = null
max_depth = 3
if params.len >= 1 then MASTER_PUB_FILE = params[0]
if params.len >= 2 then
    dp = params[1].to_int
    if typeof(dp) == "number" and dp > 0 then max_depth = dp
end if
if params.len >= 3 then parent_ip = params[2]

master_pub = read_file(MASTER_PUB_FILE)
if not master_pub then exit("Master pub key missing")

infected_file = "/root/.botnet/infected.txt"
infected_data = read_file(infected_file)
if infected_data then
    infected = infected_data.split(char(10))
else
    infected = []
end if
if infected.indexOf(my_ip) == null then
    infected.push(my_ip)
    safe_file_write(infected_file, infected.join(char(10)))
end if

// initialize modules
scanner.init(my_ip, infected, parent_ip)
exploiter.init()
deployer.init(MASTER_PUB_FILE)

current_depth = 0
if parent_ip != null then
    marker_path = "/root/.botnet/depth_markers/" + parent_ip.replace(".", "_")
    mf = get_shell.host_computer.File(marker_path)
    if mf then
        sd = mf.get_content
        if sd then
            d = sd.to_int
            if typeof(d) == "number" then current_depth = d + 1
        end if
    end if
else
    current_depth = 0
end if
if current_depth >= HARD_DEPTH_CAP then
    while true
        wait(300)
    end while
end if
if current_depth >= max_depth then
    while true
        wait(60)
    end while
end if

// store own depth marker
comp = get_shell.host_computer
if not comp.File("/root/.botnet/depth_markers") then comp.create_folder("/root/.botnet", "depth_markers")
safe_file_write("/root/.botnet/depth_markers/" + my_ip.replace(".", "_"), str(current_depth))

log_master("Worm depth " + current_depth + "/" + max_depth, "INFO")

main = function()
    fails = 0
    while true
        targets = scanner.scan_lan()
        if targets.len == 0 then
            fails = fails + 1
            if fails > 5 then wait(300); fails = 0
        else
            fails = 0
        end if
        for t in targets
            shell = exploiter.exploit_target(t)
            if shell then
                deployer.deploy_to_target(shell, t, current_depth, max_depth, infected, infected_file)
            end if
        end for
        wait(SPREAD_DELAY)
    end while
end function

main()
