// metrics.gs - Botnet metrics and monitoring system
// Provides visibility into botnet health and performance

import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/config_manager.gs")

// ============================================
// Metrics Configuration
// ============================================

METRICS_FILE = "/root/.botnet/metrics.json"
METRICS_RETENTION = 7  // days
HEARTBEAT_INTERVAL = 300  // 5 minutes

// ============================================
// Metrics Collection
// ============================================

init_metrics = function()
    if globals.metrics == null then
        globals.metrics = {
            // System metrics
            "start_time": time,
            "uptime": 0,
            "system_load": "unknown",
            "memory_usage": "unknown",
            
            // Command metrics
            "commands_executed": 0,
            "commands_failed": 0,
            "last_command": null,
            "last_command_time": 0,
            
            // Network metrics
            "connections_made": 0,
            "connections_failed": 0,
            "last_contact": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            
            // Security metrics
            "exploits_attempted": 0,
            "exploits_successful": 0,
            "suspicious_processes_killed": 0,
            "file_tampering_events": 0,
            
            // Botnet metrics
            "infected_by": null,
            "depth": 0,
            "bots_infected": 0,
            "last_heartbeat": 0,
            
            // Error metrics
            "errors": [],
            "warnings": [],
            "last_error": null
        }
    end if
end function

update_metrics = function()
    init_metrics()
    
    metrics = globals.metrics
    
    // Update uptime
    metrics["uptime"] = time - metrics["start_time"]
    
    // Get system load (simplified for GreyScript)
    procs = get_shell.host_computer.show_procs
    if procs != null then
        metrics["system_load"] = str(procs.len) + " processes"
    end if
    
    // Update last contact
    if metrics["last_contact"] == 0 then
        metrics["last_contact"] = time
    end if
    
    return metrics
end function

record_command = function(command, success=true)
    update_metrics()
    metrics = globals.metrics
    
    metrics["commands_executed"] = metrics["commands_executed"] + 1
    metrics["last_command"] = command
    metrics["last_command_time"] = time
    
    if not success then
        metrics["commands_failed"] = metrics["commands_failed"] + 1
    end if
end function

record_exploit = function(success=true)
    update_metrics()
    metrics = globals.metrics
    
    metrics["exploits_attempted"] = metrics["exploits_attempted"] + 1
    
    if success then
        metrics["exploits_successful"] = metrics["exploits_successful"] + 1
    end if
end function

record_connection = function(success=true, bytes=0)
    update_metrics()
    metrics = globals.metrics
    
    if success then
        metrics["connections_made"] = metrics["connections_made"] + 1
        metrics["bytes_sent"] = metrics["bytes_sent"] + bytes
        metrics["last_contact"] = time
    else
        metrics["connections_failed"] = metrics["connections_failed"] + 1
    end if
end function

record_security_event = function(event_type, details=null)
    update_metrics()
    metrics = globals.metrics
    
    if event_type == "suspicious_process" then
        metrics["suspicious_processes_killed"] = metrics["suspicious_processes_killed"] + 1
    else if event_type == "file_tampering" then
        metrics["file_tampering_events"] = metrics["file_tampering_events"] + 1
    end if
    
    // Add to error/warning log
    timestamp = str(time)
    event = timestamp + ": " + event_type
    if details != null then
        event = event + " - " + details
    end if
    
    if event_type.indexOf("ERROR") != null then
        metrics["errors"].push(event)
        metrics["last_error"] = event
    else
        metrics["warnings"].push(event)
    end if
    
    // Limit log size
    if metrics["errors"].len > 100 then
        metrics["errors"] = metrics["errors"][-50:]
    end if
    if metrics["warnings"].len > 100 then
        metrics["warnings"] = metrics["warnings"][-50:]
    end if
end function

record_heartbeat = function()
    update_metrics()
    metrics = globals.metrics
    metrics["last_heartbeat"] = time
end function

// ============================================
// Metrics Serialization
// ============================================

serialize_metrics = function(metrics)
    if metrics == null then return "{}"
    
    parts = []
    for key in metrics.keys
        value = metrics[key]
        
        if typeof(value) == "string" then
            parts.push(key + ":" + char(34) + value + char(34))
        else if typeof(value) == "number" then
            parts.push(key + ":" + str(value))
        else if typeof(value) == "list" then
            array_str = "["
            for i in range(0, value.len - 1)
                item = value[i]
                if typeof(item) == "string" then
                    array_str = array_str + char(34) + item + char(34)
                else
                    array_str = array_str + str(item)
                end if
                if i < value.len - 1 then
                    array_str = array_str + ","
                end if
            end for
            array_str = array_str + "]"
            parts.push(key + ":" + array_str)
        else
            parts.push(key + ":null")
        end if
    end for
    
    return "{" + parts.join(",") + "}"
end function

// ============================================
// Metrics Storage
// ============================================

save_metrics = function()
    metrics = update_metrics()
    if metrics == null then return false
    
    serialized = serialize_metrics(metrics)
    return safe_file_write(METRICS_FILE, serialized)
end function

load_metrics = function()
    data = safe_file_read(METRICS_FILE)
    if data == null then
        init_metrics()
        return globals.metrics
    end if
    
    // Simple JSON parsing for GreyScript
    metrics = parse_metrics_json(data)
    if metrics == null then
        init_metrics()
        return globals.metrics
    end if
    globals.metrics = metrics
    return metrics
end function

parse_metrics_json = function(json_str)
    // Very basic JSON parser for our metrics format
    if json_str == null or json_str == "" then return null
    
    metrics = {}
    
    // Remove braces
    content = json_str[1:-1]
    
    // Split by commas (not inside strings)
    parts = []
    current = ""
    in_string = false
    
    for i in range(0, content.len - 1)
        char = content[i]
        
        if char == char(34) then
            in_string = not in_string
        end if
        
        if char == "," and not in_string then
            if current != "" then
                parts.push(current.trim)
            end if
            current = ""
        else
            current = current + char
        end if
    end for
    
    if current != "" then
        parts.push(current.trim)
    end if
    
    // Parse key:value pairs
    for part in parts
        colon_index = part.indexOf(":")
        if colon_index == null then continue
        
        key = part[0:colon_index].trim
        value_str = part[colon_index + 1:].trim
        
        // Parse value
        if value_str == "null" then
            value = null
        else if value_str[0] == char(34) and value_str[-1] == char(34) then
            value = value_str[1:-1]  // Remove quotes
        else if value_str[0] == "[" then
            // Parse array
            value = parse_array(value_str)
        else
            value = value_str.to_int
            if typeof(value) != "number" then
                value = value_str
            end if
        end if
        
        metrics[key] = value
    end for
    
    return metrics
end function

parse_array = function(array_str)
    if array_str == null or array_str == "" then return []
    
    // Remove brackets
    content = array_str[1:-1]
    if content == "" then return []
    
    // Split by commas
    parts = content.split(",")
    result = []
    
    for part in parts
        part = part.trim
        if part[0] == char(34) and part[-1] == char(34) then
            result.push(part[1:-1])
        else
            num = part.to_int
            if typeof(num) == "number" then
                result.push(num)
            else
                result.push(part)
            end if
        end if
    end for
    
    return result
end function

// ============================================
// Metrics Reporting
// ============================================

get_metrics_summary = function()
    metrics = update_metrics()
    if metrics == null then return null
    
    return {
        "uptime": metrics["uptime"],
        "commands_executed": metrics["commands_executed"],
        "commands_failed": metrics["commands_failed"],
        "exploits_successful": metrics["exploits_successful"],
        "connections_made": metrics["connections_made"],
        "last_contact": metrics["last_contact"],
        "error_count": metrics["errors"].len,
        "warning_count": metrics["warnings"].len
    }
end function

get_health_status = function()
    metrics = update_metrics()
    if metrics == null then return "unknown"
    
    // Health check logic
    issues = []
    
    // Check for recent errors
    if metrics["errors"].len > 0 then
        last_error = metrics["last_error"]
        if last_error != null then
            error_time = last_error.split(":")[0].to_int
            if typeof(error_time) == "number" and (time - error_time) < 300 then
                issues.push("recent_errors")
            end if
        end if
    end if
    
    // Check connection health
    if time - metrics["last_contact"] > 600 then
        issues.push("no_recent_contact")
    end if
    
    // Check command failure rate
    if metrics["commands_executed"] > 10 then
        failure_rate = metrics["commands_failed"] / metrics["commands_executed"]
        if failure_rate > 0.5 then
            issues.push("high_failure_rate")
        end if
    end if
    
    // Determine status
    if issues.len == 0 then
        return "healthy"
    else if issues.len <= 2 then
        return "degraded"
    else
        return "critical"
    end if
end function

send_metrics_to_master = function(ip, master_pubkey, get_password_func)
    metrics = update_metrics()
    if metrics == null then return false
    
    // Add health status
    metrics["health_status"] = get_health_status()
    
    // Serialize and encrypt
    metrics_str = serialize_metrics(metrics)
    cipher = encrypt_command(metrics_str, master_pubkey)
    
    if cipher != null then
        return secure_send(ip, cipher, get_password_func)
    end if
    
    return false
end function

// ============================================
// Metrics Maintenance
// ============================================

cleanup_old_metrics = function()
    comp = get_shell.host_computer
    
    // Clean old metric files
    metrics_dir = comp.File("/root/.botnet")
    if metrics_dir != null then
        files = metrics_dir.get_files
        if files != null then
            cutoff_time = time - (METRICS_RETENTION * 24 * 3600)
            
            for f in files
                if f == null then continue
                if f.name.indexOf("metrics.") == 0 then
                    if f.modified < cutoff_time then
                        f.delete
                        log_master("Cleaned old metrics file: " + f.name, "INFO")
                    end if
                end if
            end for
        end if
    end if
end function

reset_metrics = function()
    init_metrics()
    metrics = globals.metrics
    
    // Reset counters but keep some system info
    metrics["commands_executed"] = 0
    metrics["commands_failed"] = 0
    metrics["exploits_attempted"] = 0
    metrics["exploits_successful"] = 0
    metrics["connections_made"] = 0
    metrics["connections_failed"] = 0
    metrics["suspicious_processes_killed"] = 0
    metrics["file_tampering_events"] = 0
    metrics["errors"] = []
    metrics["warnings"] = []
    metrics["last_error"] = null
    
    save_metrics()
    log_master("Metrics reset", "INFO")
end function

// ============================================
// Metrics Display
// ============================================

print_metrics = function()
    metrics = update_metrics()
    if metrics == null then return
    
    print("=== Botnet Metrics ===")
    print("Uptime: " + str(metrics["uptime"]) + " seconds")
    print("Commands: " + str(metrics["commands_executed"]) + " executed, " + str(metrics["commands_failed"]) + " failed")
    print("Exploits: " + str(metrics["exploits_successful"]) + "/" + str(metrics["exploits_attempted"]) + " successful")
    print("Connections: " + str(metrics["connections_made"]) + " made, " + str(metrics["connections_failed"]) + " failed")
    print("Health Status: " + get_health_status())
    
    if metrics["errors"].len > 0 then
        print("Recent Errors:")
        for error in metrics["errors"][-5:]
            print("  " + error)
        end for
    end if
    
    if metrics["warnings"].len > 0 then
        print("Recent Warnings:")
        for warning in metrics["warnings"][-5:]
            print("  " + warning)
        end for
    end if
end function
