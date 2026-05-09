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
    if result == null then return "unknown"  // ✅ Never null
    
    comp = null
    if typeof(result) == "shell" then
        comp = result.host_computer
    else if typeof(result) == "computer" then
        comp = result
    else if typeof(result) == "file" then
        comp = result.host_computer
    else
        return "unknown"  // ✅ Never null
    end if
    
    if comp == null then return "unknown"  // ✅ Never null
    
    // Test root by attempting to create a file in /root
    // This is non-destructive and tests actual write permissions
    test_name = ".root_test_" + str(floor(rnd * 9999))
    test_path = "/root/" + test_name
    
    // Try to create test file
    result = comp.touch("/root", test_name)
    if result == null then return "guest"
    
    testFile = comp.File(test_path)
    if testFile == null then return "guest"
    
    testContent = "access_test_" + str(time)
    testFile.set_content(testContent)
    
    // Verify write succeeded
    verify = testFile.get_content
    
    // ALWAYS cleanup, even if test failed (Item 18)
    if testFile != null then
        testFile.delete
    end if
    
    // Only return true if content matched
    if verify == testContent then
        return "root"
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

// Convenience wrapper for backward compatibility - now calls accessLevel directly
getUserLevel = function(result)
    return accessLevel(result)
end function

// Get username from result - returns null since username extraction isn't available
getUserName = function(result)
    // Username extraction not available in GreyScript sandbox
    return null
end function

// Check if result has specific privilege level
hasPrivilege = function(result, required_level)
    current_level = accessLevel(result)
    
    if required_level == "root" then return current_level == "root"
    if required_level == "user" then return current_level == "user" or current_level == "root"
    if required_level == "guest" then return true  // All levels have at least guest
    
    return false
end function
