// Log wiper utility — cleans traces after intrusion
// Usage: import_code("/path/to/utils/wipe_logs.gs")

wipe_logs = function(comp=null)
    if comp == null then comp = get_shell.host_computer
    logs = ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"]
    for logPath in logs
        f = comp.File(logPath)
        if f != null then
            f.set_content("")
        end if
    end for
end function
