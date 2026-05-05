// ============================================
// Unit Test: safe_path function
// Tests path traversal and security validation
// ============================================

import_code("/scripts/utils/botnet_config.gs")
import_code("/bin/slave.gs")

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
    print("Testing safe_path function...")
    print("-" * 40)
    
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
    
    // Test 11: Valid utils path
    assert("safe_path valid utils path", globals.safe_path("/scripts/utils/accessLevel.gs"), true)
    
    // Test 12: Valid tmp path
    assert("safe_path valid tmp path", globals.safe_path("/tmp/deploy_file"), true)
    
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
