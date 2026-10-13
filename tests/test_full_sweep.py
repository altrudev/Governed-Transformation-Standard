import unittest
from unittest.mock import patch
from assurance.full_sweep import run, execute, ROOT, TEST_GROUPS, MANDATORY_HOST

class ReleaseGateTests(unittest.TestCase):
    def test_missing_host_witnesses_block_release(self):
        result=run(execute_tests=False)
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["overall"],"BLOCKED")
        self.assertEqual(set(result["required_host_witnesses"]),set(MANDATORY_HOST))
    def test_successful_tests_do_not_override_missing_host_witnesses(self):
        good={"status":"PASS","exit_code":0,"output_sha256":"a"*64}
        with patch("assurance.full_sweep.execute", return_value=good):
            result=run()
        self.assertFalse(result["release_authorized"])
        self.assertEqual(len(result["test_execution"]),len(TEST_GROUPS))
    def test_command_failure_is_not_success(self):
        failure=execute(ROOT,["test_nonexistent_module_314159","-q"])
        self.assertEqual(failure["status"],"FAIL")
        self.assertNotEqual(failure["exit_code"],0)
    def test_failing_group_blocks_release(self):
        with patch("assurance.full_sweep.execute", return_value={"status":"FAIL","exit_code":1}):
            self.assertFalse(run()["release_authorized"])
