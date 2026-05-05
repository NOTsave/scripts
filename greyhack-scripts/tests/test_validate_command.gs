// ============================================
// Unit Test: validate_command function
// Tests command validation and security
// ============================================

import_code("/scripts/utils/command_validation.gs")

// Test framework
test_results = []
test_count = 0

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

// Test cases
run_tests = function()
    print("Testing validate_command function...")
    print("-" * 40)
    
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
    
    // Test 11: Valid read command
    assert("validate_command valid read", globals.validate_command("read /root/.botnet/log.txt"), true)
    
    // Test 12: Invalid read command (bad path)
    assert("validate_command invalid read", globals.validate_command("read /etc/passwd"), false)
    
    // Test 13: Valid clean command
    assert("validate_command valid clean", globals.validate_command("clean"), true)
    
    // Test 14: Valid kill command
    assert("validate_command valid kill", globals.validate_command("kill /bin/slave.gs"), true)
    
    // Test 15: Invalid kill command (bad path)
    assert("validate_command invalid kill", globals.validate_command("kill /etc/passwd"), false)
    
    // Test 16: Valid rotate command
    assert("validate_command valid rotate", globals.validate_command("rotate"), true)
    
    // Test 17: Valid broadcast command
    assert("validate_command valid broadcast", globals.validate_command("broadcast status"), true)
    
    // Test 18: Invalid broadcast (too long)
    long_broadcast = "broadcast " + "a" * 2000
    assert("validate_command long broadcast", globals.validate_command(long_broadcast), false)
    
    // Test 19: Command with special characters
    assert("validate_command special chars", globals.validate_command("run /bin/slave.gs; cat /etc/passwd"), false)
    
    // Test 20: Valid update command
    assert("validate_command valid update", globals.validate_command("update"), true)
    
    print("-" * 40)
    print("Results:")
    print("-" * 40)
    
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
    
    print("-" * 40)
    print("Tests Run: " + str(test_count))
    print("Passed: " + str(passed))
    print("Failed: " + str(failed))
    print("Success Rate: " + str(floor((passed / test_count) * 100)) + "%")
    
    if failed == 0 then
        print(green("ALL TESTS PASSED ✓"))
    else
        print(red(str(failed) + " TESTS FAILED ✗"))
    end if
end function

// Auto-run tests if executed directly
if get_shell.launch == null then
    run_tests()
end if
