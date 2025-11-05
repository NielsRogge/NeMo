# Copyright (c) 2025, NVIDIA CORPORATION.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Security Tests for CVE-002: Command Injection Vulnerability

This test suite verifies the presence of command injection vulnerabilities in the codebase.
These tests are designed to detect unsafe use of shell command execution that could allow
arbitrary command execution.

Severity: CRITICAL
Jira Issue: https://ml6team.atlassian.net/browse/DR-135

Vulnerability Description:
The application is vulnerable to command injection through unsafe use of os.system,
subprocess.call, or subprocess.run with shell=True, especially in scripts that might
process user-provided input or configuration.

Vulnerable Patterns:
1. os.system() with unsanitized input
2. subprocess.run() with shell=True
3. subprocess.call() with shell=True
4. os.popen() with unsanitized input

Attack Vector:
An attacker could inject malicious shell commands through user-controlled input that
is passed to shell command execution functions without proper sanitization.

Example:
    user_input = "; rm -rf /"  # Malicious input
    os.system(f"echo {user_input}")  # Command injection
"""

import ast
import os
import re
import subprocess
from pathlib import Path
from typing import List, Tuple
from unittest.mock import MagicMock, mock_open, patch

import pytest


class TestCommandInjectionVulnerability:
    """
    Test suite to detect command injection vulnerabilities in the codebase.
    
    These tests verify that vulnerable patterns exist in the code that could
    allow command injection attacks. The tests are meant to document the
    vulnerability, not to fix it.
    """

    @pytest.fixture
    def nemo_root(self) -> Path:
        """Get the root directory of the NeMo project."""
        return Path(__file__).parent.parent

    @pytest.fixture
    def vulnerable_files(self) -> List[str]:
        """
        List of files known to contain command injection vulnerabilities.
        
        These files were identified in the CVE-002 security audit.
        """
        return [
            'nemo/utils/cloud.py',
            'nemo/collections/llm/deploy/base.py',
            'scripts/dataset_processing/get_commonvoice_data.py',
        ]

    @pytest.mark.unit
    def test_os_system_usage_exists(self, nemo_root: Path, vulnerable_files: List[str]):
        """
        Test that os.system() calls exist in the codebase.
        
        This test verifies the presence of os.system() calls which are inherently
        vulnerable to command injection when used with unsanitized input.
        
        Expected: This test should PASS, confirming the vulnerability exists.
        """
        os_system_found = False
        findings = []

        for file_path in vulnerable_files:
            full_path = nemo_root / file_path
            if not full_path.exists():
                continue

            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Search for os.system usage
            if 'os.system' in content:
                os_system_found = True
                # Find line numbers
                for i, line in enumerate(content.split('\n'), 1):
                    if 'os.system' in line:
                        findings.append(f"{file_path}:{i}: {line.strip()}")

        assert os_system_found, (
            "os.system() usage not found in expected files. "
            f"Checked files: {vulnerable_files}\n"
            f"This suggests the vulnerability may have been patched."
        )

        print("\n[CVE-002] Found os.system() usage in the following locations:")
        for finding in findings:
            print(f"  - {finding}")

    @pytest.mark.unit
    def test_subprocess_shell_true_usage_exists(self, nemo_root: Path, vulnerable_files: List[str]):
        """
        Test that subprocess calls with shell=True exist in the codebase.
        
        This test verifies the presence of subprocess.run/call/Popen with shell=True,
        which is vulnerable to command injection when used with unsanitized input.
        
        Expected: This test should PASS, confirming the vulnerability exists.
        """
        shell_true_found = False
        findings = []

        for file_path in vulnerable_files:
            full_path = nemo_root / file_path
            if not full_path.exists():
                continue

            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Search for subprocess with shell=True
            pattern = r'subprocess\.(run|call|Popen).*shell\s*=\s*True'
            if re.search(pattern, content, re.MULTILINE | re.DOTALL):
                shell_true_found = True
                for i, line in enumerate(content.split('\n'), 1):
                    if re.search(pattern, line):
                        findings.append(f"{file_path}:{i}: {line.strip()}")

        assert shell_true_found, (
            "subprocess with shell=True not found in expected files. "
            f"Checked files: {vulnerable_files}\n"
            f"This suggests the vulnerability may have been patched."
        )

        print("\n[CVE-002] Found subprocess with shell=True in the following locations:")
        for finding in findings:
            print(f"  - {finding}")

    @pytest.mark.unit
    def test_cloud_py_vulnerable_os_system(self, nemo_root: Path):
        """
        Test specific vulnerability in nemo/utils/cloud.py.
        
        This file contains os.system() call at line 115 that executes shell commands
        to install system libraries. While the command is hardcoded, the use of
        os.system() is inherently unsafe.
        
        Vulnerable code:
            os.system('chmod 777 /tmp && apt-get update && apt-get install -y libsndfile1 ffmpeg')
        
        Expected: This test should PASS, confirming the vulnerability exists.
        """
        cloud_py = nemo_root / 'nemo' / 'utils' / 'cloud.py'
        
        if not cloud_py.exists():
            pytest.skip(f"File not found: {cloud_py}")

        with open(cloud_py, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check for the specific vulnerable line
        vulnerable_pattern = r"os\.system\(['\"]chmod 777 /tmp && apt-get update && apt-get install"
        
        assert re.search(vulnerable_pattern, content), (
            "Expected os.system() vulnerability not found in nemo/utils/cloud.py. "
            "This suggests the vulnerability may have been patched."
        )

        print("\n[CVE-002] Confirmed: nemo/utils/cloud.py contains os.system() vulnerability")
        print("  Location: _install_system_libraries() function")
        print("  Risk: Command injection possible if function parameters were added")

    @pytest.mark.unit
    def test_deploy_base_py_vulnerable_subprocess(self, nemo_root: Path):
        """
        Test specific vulnerability in nemo/collections/llm/deploy/base.py.
        
        This file uses subprocess.run with shell=True at line 36 to execute
        environment variable queries. The command is dynamically constructed
        using an f-string with the 'prefix' parameter.
        
        Vulnerable code:
            cmd = f"env | grep ^{prefix} | cut -d= -f1"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        Risk: If 'prefix' comes from user input, arbitrary commands could be injected.
        
        Expected: This test should PASS, confirming the vulnerability exists.
        """
        deploy_base_py = nemo_root / 'nemo' / 'collections' / 'llm' / 'deploy' / 'base.py'
        
        if not deploy_base_py.exists():
            pytest.skip(f"File not found: {deploy_base_py}")

        with open(deploy_base_py, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check for the specific vulnerable pattern
        vulnerable_pattern = r'subprocess\.run\(.*shell\s*=\s*True'
        
        assert re.search(vulnerable_pattern, content), (
            "Expected subprocess.run with shell=True not found in "
            "nemo/collections/llm/deploy/base.py. "
            "This suggests the vulnerability may have been patched."
        )

        print("\n[CVE-002] Confirmed: nemo/collections/llm/deploy/base.py contains subprocess vulnerability")
        print("  Location: unset_vars_with_prefix() function")
        print("  Risk: Command injection if prefix parameter is user-controlled")

    @pytest.mark.unit
    def test_commonvoice_script_vulnerable_subprocess(self, nemo_root: Path):
        """
        Test specific vulnerability in scripts/dataset_processing/get_commonvoice_data.py.
        
        This script uses subprocess.run with shell=True to execute wget commands
        constructed from user-controllable arguments and URLs.
        
        Vulnerable code (line 175):
            commands = " ".join([
                'wget', '--user-agent', '"Mozilla/5.0..."',
                '-O', output_archive_filename, f'{COMMON_VOICE_URL}'
            ])
            subprocess.run(commands, shell=True, stderr=sys.stderr, stdout=sys.stdout)
        
        Risk: Command injection through COMMON_VOICE_URL or filename parameters.
        
        Expected: This test should PASS, confirming the vulnerability exists.
        """
        script_path = nemo_root / 'scripts' / 'dataset_processing' / 'get_commonvoice_data.py'
        
        if not script_path.exists():
            pytest.skip(f"File not found: {script_path}")

        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check for the specific vulnerable pattern
        vulnerable_pattern = r'subprocess\.run\(commands,\s*shell\s*=\s*True'
        
        assert re.search(vulnerable_pattern, content), (
            "Expected subprocess.run with shell=True not found in "
            "scripts/dataset_processing/get_commonvoice_data.py. "
            "This suggests the vulnerability may have been patched."
        )

        print("\n[CVE-002] Confirmed: get_commonvoice_data.py contains subprocess vulnerability")
        print("  Location: main() function")
        print("  Risk: Command injection through URL or filename parameters")

    @pytest.mark.unit
    def test_command_injection_attack_vector_simulation(self):
        """
        Simulate a command injection attack to demonstrate the vulnerability.
        
        This test demonstrates how an attacker could exploit the vulnerability
        by injecting malicious commands through unsanitized input.
        
        NOTE: This test uses mocking to prevent actual command execution.
        
        Expected: This test should PASS, showing the attack is possible.
        """
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout="", returncode=0)

            # Simulate vulnerable code pattern from deploy/base.py
            # Attacker-controlled input
            malicious_prefix = "SLURM_; echo INJECTED; #"
            
            # Vulnerable code pattern (simplified from actual code)
            cmd = f"env | grep ^{malicious_prefix} | cut -d= -f1"
            subprocess.run(cmd, shell=True, capture_output=True, text=True)

            # Verify the vulnerable command was constructed
            mock_run.assert_called_once()
            executed_cmd = mock_run.call_args[0][0]
            
            # The injected command should be present in the executed command
            assert "echo INJECTED" in executed_cmd, (
                "Command injection was not successful. "
                "This suggests proper input sanitization is in place."
            )

            print("\n[CVE-002] Command injection attack vector confirmed:")
            print(f"  Malicious input: {malicious_prefix}")
            print(f"  Executed command: {executed_cmd}")
            print("  Result: Arbitrary command execution is possible")

    @pytest.mark.unit
    def test_os_system_attack_vector_simulation(self):
        """
        Simulate command injection through os.system() to demonstrate vulnerability.
        
        This test demonstrates how os.system() with unsanitized input allows
        command injection attacks.
        
        NOTE: This test uses mocking to prevent actual command execution.
        
        Expected: This test should PASS, showing the attack is possible.
        """
        with patch('os.system') as mock_system:
            mock_system.return_value = 0

            # Simulate vulnerable code pattern
            # Attacker-controlled input
            malicious_input = "echo safe; rm -rf /tmp/important; #"
            
            # Vulnerable code pattern (simplified)
            command = f"echo {malicious_input}"
            os.system(command)

            # Verify the vulnerable command was executed
            mock_system.assert_called_once()
            executed_cmd = mock_system.call_args[0][0]
            
            # The injected command should be present
            assert "rm -rf" in executed_cmd, (
                "Command injection was not successful. "
                "This suggests proper input sanitization is in place."
            )

            print("\n[CVE-002] os.system() command injection confirmed:")
            print(f"  Malicious input: {malicious_input}")
            print(f"  Executed command: {executed_cmd}")
            print("  Result: Arbitrary command execution is possible")

    @pytest.mark.unit
    def test_scan_codebase_for_vulnerable_patterns(self, nemo_root: Path):
        """
        Comprehensive scan of the codebase for command injection vulnerabilities.
        
        This test scans Python files in the nemo/ and scripts/ directories for
        vulnerable patterns:
        - os.system()
        - os.popen()
        - subprocess.run/call/Popen with shell=True
        
        Expected: This test should PASS and report all findings.
        """
        vulnerable_patterns = [
            (r'os\.system\(', 'os.system() usage'),
            (r'os\.popen\(', 'os.popen() usage'),
            (r'subprocess\.(run|call|Popen).*shell\s*=\s*True', 'subprocess with shell=True'),
        ]

        findings = {}
        
        # Scan nemo/ and scripts/ directories
        for directory in ['nemo', 'scripts']:
            dir_path = nemo_root / directory
            if not dir_path.exists():
                continue

            for py_file in dir_path.rglob('*.py'):
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    for pattern, description in vulnerable_patterns:
                        if re.search(pattern, content):
                            relative_path = py_file.relative_to(nemo_root)
                            if relative_path not in findings:
                                findings[relative_path] = []
                            
                            # Find specific line numbers
                            for i, line in enumerate(content.split('\n'), 1):
                                if re.search(pattern, line):
                                    findings[relative_path].append((i, description, line.strip()))
                except Exception:
                    # Skip files that can't be read
                    continue

        assert len(findings) > 0, (
            "No vulnerable patterns found in the codebase. "
            "This suggests all vulnerabilities have been patched."
        )

        print(f"\n[CVE-002] Comprehensive scan found {len(findings)} vulnerable files:")
        for file_path, issues in sorted(findings.items()):
            print(f"\n  {file_path}:")
            for line_num, description, line_content in issues:
                print(f"    Line {line_num}: {description}")
                print(f"      {line_content[:80]}...")

    @pytest.mark.unit
    def test_verify_no_input_sanitization(self, nemo_root: Path):
        """
        Verify that input sanitization is not implemented for vulnerable functions.
        
        This test checks whether shlex.quote() or similar sanitization functions
        are used near the vulnerable code locations. The absence of sanitization
        confirms the vulnerability.
        
        Expected: This test should PASS if no sanitization is found.
        """
        vulnerable_files = [
            'nemo/utils/cloud.py',
            'nemo/collections/llm/deploy/base.py',
            'scripts/dataset_processing/get_commonvoice_data.py',
        ]

        files_without_sanitization = []

        for file_path in vulnerable_files:
            full_path = nemo_root / file_path
            if not full_path.exists():
                continue

            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check for sanitization functions
            has_sanitization = (
                'shlex.quote' in content or
                'pipes.quote' in content or
                'sanitize' in content.lower()
            )

            if not has_sanitization:
                files_without_sanitization.append(file_path)

        assert len(files_without_sanitization) > 0, (
            "All vulnerable files appear to have input sanitization. "
            "This suggests the vulnerability may have been partially mitigated."
        )

        print(f"\n[CVE-002] Found {len(files_without_sanitization)} files without input sanitization:")
        for file_path in files_without_sanitization:
            print(f"  - {file_path}")
        print("\n  Recommendation: Implement shlex.quote() or equivalent sanitization")


class TestCommandInjectionRemediation:
    """
    Test suite documenting proper remediation patterns.
    
    These tests demonstrate the CORRECT way to handle shell commands safely.
    They serve as reference examples for fixing the vulnerabilities.
    """

    @pytest.mark.unit
    def test_safe_subprocess_without_shell(self):
        """
        Demonstrate safe subprocess usage without shell=True.
        
        This is the RECOMMENDED approach: Pass arguments as a list without shell=True.
        This prevents command injection because the shell does not interpret the arguments.
        """
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            # SAFE: Using list of arguments without shell=True
            safe_cmd = ['echo', 'user_input; rm -rf /']
            subprocess.run(safe_cmd, capture_output=True, text=True)

            # Verify the command was called correctly
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            
            # The malicious input is treated as a literal string, not executed
            assert isinstance(args, list), "Arguments should be passed as a list"
            assert args == safe_cmd, "Arguments should not be modified"

            print("\n[CVE-002] Safe pattern demonstrated:")
            print(f"  Command: {safe_cmd}")
            print("  Result: Malicious input is treated as literal text, not executed")

    @pytest.mark.unit
    def test_safe_subprocess_with_shlex_quote(self):
        """
        Demonstrate safe subprocess usage with shlex.quote() for shell sanitization.
        
        If shell=True is ABSOLUTELY necessary, use shlex.quote() to escape
        shell metacharacters in user-provided input.
        """
        import shlex

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")

            # User input that would be dangerous without sanitization
            user_input = "value; rm -rf /"
            
            # SAFE: Using shlex.quote() to sanitize input before shell execution
            safe_cmd = f"echo {shlex.quote(user_input)}"
            subprocess.run(safe_cmd, shell=True, capture_output=True, text=True)

            # Verify the command was properly sanitized
            mock_run.assert_called_once()
            executed_cmd = mock_run.call_args[0][0]
            
            # The input should be quoted and escaped
            assert shlex.quote(user_input) in executed_cmd
            
            print("\n[CVE-002] Safe sanitization pattern demonstrated:")
            print(f"  Original input: {user_input}")
            print(f"  Sanitized command: {executed_cmd}")
            print("  Result: Shell metacharacters are properly escaped")

    @pytest.mark.unit
    def test_unsafe_vs_safe_comparison(self):
        """
        Side-by-side comparison of unsafe vs safe command execution patterns.
        
        This test clearly demonstrates the difference between vulnerable and
        secure code patterns.
        """
        import shlex

        user_input = "; cat /etc/passwd"

        # UNSAFE patterns (vulnerable to command injection)
        unsafe_patterns = [
            f"os.system('echo {user_input}')",
            f"subprocess.run('echo {user_input}', shell=True)",
            f"subprocess.call('echo {user_input}', shell=True)",
        ]

        # SAFE patterns (properly secured)
        safe_patterns = [
            f"subprocess.run(['echo', '{user_input}'], shell=False)",
            f"subprocess.run('echo {shlex.quote(user_input)}', shell=True)",
        ]

        print("\n[CVE-002] Unsafe vs Safe Patterns Comparison:")
        print("\n  UNSAFE (Vulnerable to Command Injection):")
        for pattern in unsafe_patterns:
            print(f"    ❌ {pattern}")
        
        print("\n  SAFE (Protected Against Command Injection):")
        for pattern in safe_patterns:
            print(f"    ✓ {pattern}")

        # This test always passes - it's for documentation purposes
        assert True, "Pattern comparison completed"
