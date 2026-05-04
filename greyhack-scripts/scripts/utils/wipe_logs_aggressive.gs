// wipe_logs_aggressive.gs - Aggressive log wiping with explicit imports

import_code("/scripts/utils/accessLevel.gs")
import_code("/lib/lib_common.gs")

// Aggressive wipe - also removes /etc/passwd and sensitive files
wipe_logs_aggressive = function(comp)
    if comp == null then comp = get_shell.host_computer
    
    // Import standard wipe_logs function
    import_code("/scripts/utils/wipe_logs.gs")
    
    // Standard wipe first
    wipe_logs(comp)
    
    // Remove /etc/passwd - check permissions first
    passwd = comp.File("/etc/passwd")
    if passwd != null then
        // Only delete if we're root AND passwd is a regular file (not a symlink)
        if accessLevel(get_shell) == "root" and passwd.is_binary == 0 then
            // Clear the file content first
            passwd.set_content("")
            // Then delete the file
            result = passwd.delete
            if result != "" then
                log_master("Could not delete /etc/passwd: " + result, "WARN")
            end if
        end if
    end if
    
    // Remove Bank.txt and Mail.txt across all users
    bank_paths = ["/root/Config/Bank.txt"]
    mail_paths = ["/root/Config/Mail.txt"]
    home = comp.File("/home")
    if home != null then
        home_folders = home.get_folders
        if home_folders != null then
            for user_folder in home_folders
                if user_folder != null and user_folder.name != "guest" then
                    bank_paths.push("/home/" + user_folder.name + "/Config/Bank.txt")
                    mail_paths.push("/home/" + user_folder.name + "/Config/Mail.txt")
                end if
            end for
        end if
    end if
    
    for bp in bank_paths
        bf = comp.File(bp)
        if bf != null and bf.has_permission("w") then
            bf.delete
        end if
    end for
    for mp in mail_paths
        mf = comp.File(mp)
        if mf != null and mf.has_permission("w") then
            mf.delete
        end if
    end for
    
    log_master("Aggressive wipe completed", "INFO")
end function
