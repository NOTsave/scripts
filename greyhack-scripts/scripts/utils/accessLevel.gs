// Access level checker — determines privilege level on target
// Usage: import_code("/path/to/utils/accessLevel.gs")
// Returns: "root", "user", "guest", or "unknown"
// Enhanced with GLASSPOOL-style checkUser function

toFolder = function(fileObj, folderPath)
    if fileObj == null then return null
    if folderPath == null then return null
    
    comp = fileObj.host_computer
    if comp == null then return null
    
    parts = folderPath.split("/")
    currentPath = ""
    
    for part in parts
        if part == "" or part == "." then continue
        if currentPath == "" then
            currentPath = "/" + part
        else
            currentPath = currentPath + "/" + part
        end if
        currentFile = comp.File(currentPath)
        if currentFile == null then return null
    end for
    
    return currentFile
end function

accessLevel = function(result)
    if result == null then return "unknown"
    
    comp = null
    if typeof(result) == "shell" then
        comp = result.host_computer
    else if typeof(result) == "computer" then
        comp = result
    else if typeof(result) == "file" then
        comp = result.host_computer
    else
        return "unknown"
    end if
    
    if comp == null then return "unknown"
    
    // Test root by attempting set_owner on /etc
    etcFolder = comp.File("/etc")
    if etcFolder != null then
        // Empty string return means success (root)
        setOwnerResult = etcFolder.set_owner("root")
        if setOwnerResult == "" then return "root"
    end if
    
    // Check for user level — look for readable /home subfolders
    homeFolder = comp.File("/home")
    if homeFolder == null then return "guest"
    
    homeFolders = homeFolder.get_folders
    if homeFolders == null then return "guest"
    
    for folder in homeFolders
        folderName = folder.name
        // Skip root and guest folders
        if folderName == "root" or folderName == "guest" then continue
        if folder.has_permission("r") then return "user"
    end for
    
    // Fall back to guest
    return "guest"
end function

// GLASSPOOL-style user privilege checker - cleaner and more comprehensive
checkUser = function(result)
    if result == null then return {"level": "unknown", "user": null, "shell": null}
    
    comp = null
    shell = null
    
    if typeof(result) == "shell" then
        comp = result.host_computer
        shell = result
    else if typeof(result) == "computer" then
        comp = result
    else if typeof(result) == "file" then
        comp = result.host_computer
    else
        return {"level": "unknown", "user": null, "shell": null}
    end if
    
    if comp == null then return {"level": "unknown", "user": null, "shell": null}
    
    // Test root via multiple methods
    
    // Method 1: Try set_owner on /etc (most reliable)
    etcFolder = comp.File("/etc")
    if etcFolder != null then
        setOwnerResult = etcFolder.set_owner("root")
        // Empty string means success (root)
        if setOwnerResult == "" then return "root"
        // Some versions return 1 for success
        if setOwnerResult == 1 then return "root"
        // Some versions return true
        if setOwnerResult == true then return "root"
    end if
    
    // Method 2: Try reading /etc/shadow (root-only in some configs)
    shadowFile = comp.File("/etc/shadow")
    if shadowFile != null then
        if shadowFile.has_permission("r") then
            // If we can read shadow, almost certainly root
            return "root"
        end if
    end if
    
    // Method 3: Try creating a file in /root
    rootDir = comp.File("/root")
    if rootDir != null then
        if rootDir.has_permission("w") then
            return "root"
        end if
    end if
    
    // Test user level - check for readable home directories
    homeFolder = comp.File("/home")
    if homeFolder == null then return "guest"
    
    homeFolders = homeFolder.get_folders
    if homeFolders == null then return "guest"
    
    // Check for any non-root/guest home directory with read access
    for folder in homeFolders
        folderName = folder.name
        if folderName == "root" or folderName == "guest" then continue
        if folder.has_permission("r") then return "user"
    end for
    
    // Fall back to guest
    return "guest"
end function

// Convenience wrapper for backward compatibility
getUserLevel = function(result)
    user_info = checkUser(result)
    return user_info["level"]
end function

// Get username from result
getUserName = function(result)
    user_info = checkUser(result)
    return user_info["user"]
end function

// Check if result has specific privilege level
hasPrivilege = function(result, required_level)
    user_info = checkUser(result)
    current_level = user_info["level"]
    
    if required_level == "root" then return current_level == "root"
    if required_level == "user" then return current_level == "user" or current_level == "root"
    if required_level == "guest" then return true  // All levels have at least guest
    
    return false
end function
