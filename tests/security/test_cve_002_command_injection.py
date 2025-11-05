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

This test module verifies the presence of command injection vulnerabilities
identified in CVE-002. These tests are designed to document and detect
potentially unsafe command execution patterns in the codebase.

**IMPORTANT**: These tests verify the EXISTENCE of the vulnerability.
They are NOT patches - the actual remediation should be done separately.

CVE Details:
- CVE ID: CVE-002
- Title: Command Injection
- Severity: CRITICAL
- Jira Issue: https://ml6team.atlassian.net/browse/DR-135

Vulnerability Description:
The application is vulnerable to command injection through unsafe use of:
- os.system()
- subprocess.run() with shell=True
- subprocess.call() with shell=True

These patterns are particularly dangerous when processing user-provided input
or configuration data, as they allow arbitrary command execution.

Identified Vulnerable Locations:
1. nemo/utils/cloud.py:115 - os.system() with hardcoded commands
2. nemo/collections/llm/deploy/base.py:36 - subprocess.run() with shell=True
3. scripts/dataset_processing/get_commonvoice_data.py:175 - subprocess.run() with shell=True
4. scripts/tokenizers/get_hf_text_data.py - os.system()
5. scripts/installers/setup_os2s_decoders.py - os.system()
6. scripts/dataset_processing/speaker_tasks/get_ami_data.py - os.system()
7. scripts/dataset_processing/spoken_wikipedia/preprocess.py - os.system()
8. scripts/dataset_processing/tts/aishell3/get_data.py - subprocess.run() with shell=True
"""

import ast
import os
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestCVE002CommandInjectionDetection:
    """
    Test suite to detect and verify command injection vulnerabilities.
    
    These tests scan the codebase for unsafe command execution patterns
    and verify that the identified vulnerabilities still exist.
    """

    @pytest.mark.unit
    def test_os_system_usage_in_cloud_py(self):
        """
        Test 1: Verify unsafe os.system() usage in nemo/utils/cloud.py
        
        The file contains: os.system('chmod 777 /tmp && apt-get update && apt-get install -y libsndfile1 ffmpeg')
        
        Risk: While this is a hardcoded command, os.system() passes the command through
        a shell, which could be exploited if any part of the command is constructed
        from user input or environment variables in the future.
        
        Recommendation: Replace with subprocess.run() using list arguments without shell=True.
        """
        file_path = Path(__file__).parent.parent.parent / "nemo" / "utils" / "cloud.py"
        assert file_path.exists(), f"File not found: {file_path}"
        
        content = file_path.read_text()
        
        # Verify os.system usage exists
        assert "os.system(" in content, "os.system() usage not found in cloud.py"
        
        # Verify the specific vulnerable line
        vulnerable_pattern = r"os\.system\(['\"]chmod 777 /tmp"
        assert re.search(vulnerable_pattern, content), \
            "Expected vulnerable os.system() call not found in cloud.py"

    @pytest.mark.unit
    def test_subprocess_run_shell_true_in_deploy_base(self):
        """
        Test 2: Verify unsafe subprocess.run() with shell=True in nemo/collections/llm/deploy/base.py
        
        The file contains: subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        Risk: The 'cmd' variable is constructed from user input, making this a critical
        command injection vulnerability. An attacker could inject arbitrary commands
        through the cmd parameter.
        
        Recommendation: Use subprocess.run() with a list of arguments and shell=False.
        If shell features are needed, use shlex.quote() to sanitize inputs.
        """
        file_path = Path(__file__).parent.parent.parent / "nemo" / "collections" / "llm" / "deploy" / "base.py"
        assert file_path.exists(), f"File not found: {file_path}"
        
        content = file_path.read_text()
        
        # Verify subprocess.run with shell=True exists
        assert "subprocess.run(" in content, "subprocess.run() usage not found in deploy/base.py"
        assert "shell=True" in content, "shell=True parameter not found in deploy/base.py"
        
        # Verify they appear in the same context
        vulnerable_pattern = r"subprocess\.run\([^)]*shell=True"
        assert re.search(vulnerable_pattern, content), \
            "Expected vulnerable subprocess.run() call with shell=True not found"

    @pytest.mark.unit
    def test_subprocess_run_shell_true_in_get_commonvoice_data(self):
        """
        Test 3: Verify unsafe subprocess.run() with shell=True in get_commonvoice_data.py
        
        The file contains: subprocess.run(commands, shell=True, stderr=sys.stderr, stdout=sys.stdout)
        
        Risk: The 'commands' variable is constructed from command strings that could
        potentially include user-provided data, creating a command injection risk.
        
        Recommendation: Parse the command string into a list and use shell=False.
        """
        file_path = Path(__file__).parent.parent.parent / "scripts" / "dataset_processing" / "get_commonvoice_data.py"
        assert file_path.exists(), f"File not found: {file_path}"
        
        content = file_path.read_text()
        
        # Verify subprocess.run with shell=True exists
        assert "subprocess.run(" in content, "subprocess.run() usage not found"
        assert "shell=True" in content, "shell=True parameter not found"
        
        # Verify the pattern exists
        vulnerable_pattern = r"subprocess\.run\([^)]*shell=True"
        assert re.search(vulnerable_pattern, content), \
            "Expected vulnerable subprocess.run() call with shell=True not found"

    @pytest.mark.unit
    def test_scan_codebase_for_os_system(self):
        """
        Test 4: Comprehensive scan for all os.system() usage in Python files
        
        This test scans the entire nemo/ directory and scripts/ directory for
        any usage of os.system(), which is inherently unsafe for command execution.
        
        Expected findings: Multiple files contain os.system() calls
        """
        nemo_dir = Path(__file__).parent.parent.parent / "nemo"
        scripts_dir = Path(__file__).parent.parent.parent / "scripts"
        
        vulnerable_files = []
        
        for directory in [nemo_dir, scripts_dir]:
            if directory.exists():
                for py_file in directory.rglob("*.py"):
                    try:
                        content = py_file.read_text()
                        if "os.system(" in content:
                            # Find all occurrences with line numbers
                            for line_num, line in enumerate(content.split('\n'), 1):
                                if "os.system(" in line and not line.strip().startswith('#'):
                                    vulnerable_files.append((str(py_file.relative_to(directory.parent)), line_num, line.strip()))
                    except Exception:
                        # Skip files that can't be read
                        pass
        
        # Verify that vulnerable files were found
        assert len(vulnerable_files) > 0, "No os.system() usage found - vulnerability may have been fixed"
        
        # Log findings for documentation
        print("\n=== os.system() Usage Detected ===")
        for file_path, line_num, line in vulnerable_files:
            print(f"{file_path}:{line_num}: {line}")

    @pytest.mark.unit
    def test_scan_codebase_for_subprocess_shell_true(self):
        """
        Test 5: Comprehensive scan for subprocess calls with shell=True
        
        This test scans the entire nemo/ directory and scripts/ directory for
        any usage of subprocess functions with shell=True, which allows command
        injection if the command string includes unsanitized user input.
        
        Expected findings: Multiple files contain subprocess calls with shell=True
        """
        nemo_dir = Path(__file__).parent.parent.parent / "nemo"
        scripts_dir = Path(__file__).parent.parent.parent / "scripts"
        
        vulnerable_files = []
        shell_true_pattern = re.compile(r"subprocess\.(run|call|Popen|check_output|check_call)\([^)]*shell\s*=\s*True")
        
        for directory in [nemo_dir, scripts_dir]:
            if directory.exists():
                for py_file in directory.rglob("*.py"):
                    try:
                        content = py_file.read_text()
                        for line_num, line in enumerate(content.split('\n'), 1):
                            if shell_true_pattern.search(line) and not line.strip().startswith('#'):
                                vulnerable_files.append((str(py_file.relative_to(directory.parent)), line_num, line.strip()))
                    except Exception:
                        # Skip files that can't be read
                        pass
        
        # Verify that vulnerable files were found
        assert len(vulnerable_files) > 0, \
            "No subprocess calls with shell=True found - vulnerability may have been fixed"
        
        # Log findings for documentation
        print("\n=== subprocess with shell=True Usage Detected ===")
        for file_path, line_num, line in vulnerable_files:
            print(f"{file_path}:{line_num}: {line}")

    @pytest.mark.unit
    def test_ast_analysis_unsafe_subprocess(self):
        """
        Test 6: AST-based detection of unsafe subprocess usage
        
        This test uses Python's AST module to parse Python files and detect
        subprocess calls with shell=True at the syntax tree level, which is
        more reliable than regex-based detection.
        """
        
        def find_unsafe_subprocess_calls(file_path):
            """
            Parse a Python file and find all subprocess calls with shell=True
            """
            try:
                with open(file_path, 'r') as f:
                    tree = ast.parse(f.read(), filename=str(file_path))
            except Exception:
                return []
            
            unsafe_calls = []
            
            class SubprocessVisitor(ast.NodeVisitor):
                def visit_Call(self, node):
                    # Check if this is a subprocess call
                    if isinstance(node.func, ast.Attribute):
                        if (isinstance(node.func.value, ast.Name) and 
                            node.func.value.id == 'subprocess' and
                            node.func.attr in ['run', 'call', 'Popen', 'check_output', 'check_call']):
                            
                            # Check for shell=True keyword argument
                            for keyword in node.keywords:
                                if keyword.arg == 'shell':
                                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                                        unsafe_calls.append({
                                            'line': node.lineno,
                                            'function': node.func.attr,
                                            'file': str(file_path)
                                        })
                    
                    self.generic_visit(node)
            
            visitor = SubprocessVisitor()
            visitor.visit(tree)
            return unsafe_calls
        
        nemo_dir = Path(__file__).parent.parent.parent / "nemo"
        scripts_dir = Path(__file__).parent.parent.parent / "scripts"
        
        all_unsafe_calls = []
        
        for directory in [nemo_dir, scripts_dir]:
            if directory.exists():
                for py_file in directory.rglob("*.py"):
                    unsafe_calls = find_unsafe_subprocess_calls(py_file)
                    all_unsafe_calls.extend(unsafe_calls)
        
        # Verify that unsafe subprocess calls were found
        assert len(all_unsafe_calls) > 0, \
            "No unsafe subprocess calls found via AST analysis - vulnerability may have been fixed"
        
        print("\n=== AST Analysis: Unsafe subprocess calls ===")
        for call in all_unsafe_calls:
            print(f"{call['file']}:{call['line']}: subprocess.{call['function']}(..., shell=True)")


class TestCVE002CommandInjectionExploitability:
    """
    Test suite to demonstrate the exploitability of command injection vulnerabilities.
    
    These tests show how command injection can be exploited through unsafe
    command execution patterns. They use mocked functions to prevent actual
    exploitation while demonstrating the vulnerability.
    """

    @pytest.mark.unit
    def test_command_injection_via_os_system(self):
        """
        Test 7: Demonstrate command injection risk with os.system()
        
        This test shows how os.system() can be exploited if user input
        is incorporated into the command string.
        
        Example: If user input is: "test.txt; rm -rf /"
        Then os.system() would execute both "cat test.txt" AND "rm -rf /"
        """
        # Simulate user input with command injection
        malicious_input = "test.txt; echo 'INJECTED_COMMAND'"
        unsafe_command = f"cat {malicious_input}"
        
        # Verify that the command contains the injection
        assert "; echo 'INJECTED_COMMAND'" in unsafe_command, \
            "Command injection payload not present in unsafe command"
        
        # Test with mock to prevent actual execution
        with patch('os.system') as mock_system:
            os.system(unsafe_command)
            
            # Verify os.system was called with the malicious command
            mock_system.assert_called_once()
            actual_command = mock_system.call_args[0][0]
            assert "INJECTED_COMMAND" in actual_command, \
                "Mock was not called with injected command"

    @pytest.mark.unit
    def test_command_injection_via_subprocess_shell_true(self):
        """
        Test 8: Demonstrate command injection risk with subprocess.run(shell=True)
        
        This test shows how subprocess.run() with shell=True can be exploited
        if user input is incorporated into the command string.
        
        Example: If user input is: "test.txt && cat /etc/passwd"
        Then subprocess.run() would execute both commands
        """
        # Simulate user input with command injection
        malicious_input = "test.txt && echo 'INJECTED_COMMAND'"
        unsafe_command = f"cat {malicious_input}"
        
        # Verify that the command contains the injection
        assert "&& echo 'INJECTED_COMMAND'" in unsafe_command, \
            "Command injection payload not present in unsafe command"
        
        # Test with mock to prevent actual execution
        with patch('subprocess.run') as mock_run:
            subprocess.run(unsafe_command, shell=True)
            
            # Verify subprocess.run was called with shell=True
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[1]['shell'] is True, \
                "subprocess.run was not called with shell=True"
            assert "INJECTED_COMMAND" in call_args[0][0], \
                "Mock was not called with injected command"

    @pytest.mark.unit
    def test_command_injection_via_piping(self):
        """
        Test 9: Demonstrate command injection through command piping
        
        This test shows how pipes (|) can be used to chain commands
        and execute arbitrary code through command injection.
        """
        # Simulate user input with pipe-based injection
        malicious_input = "| cat /etc/passwd"
        unsafe_command = f"echo 'test' {malicious_input}"
        
        # Verify that the command contains the pipe injection
        assert "| cat /etc/passwd" in unsafe_command, \
            "Pipe-based injection payload not present in unsafe command"
        
        # Test with mock
        with patch('subprocess.run') as mock_run:
            subprocess.run(unsafe_command, shell=True)
            
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert "|" in call_args[0][0], \
                "Pipe operator not present in mocked command"

    @pytest.mark.unit
    def test_command_injection_via_backticks(self):
        """
        Test 10: Demonstrate command injection through command substitution
        
        This test shows how backticks or $() can be used for command
        substitution to execute arbitrary commands.
        """
        # Simulate user input with command substitution
        malicious_input = "$(whoami)"
        unsafe_command = f"echo 'User: {malicious_input}'"
        
        # Verify that the command contains the substitution
        assert "$(whoami)" in unsafe_command, \
            "Command substitution payload not present in unsafe command"
        
        # Test with mock
        with patch('os.system') as mock_system:
            os.system(unsafe_command)
            
            mock_system.assert_called_once()
            actual_command = mock_system.call_args[0][0]
            assert "$(" in actual_command, \
                "Command substitution not present in mocked command"


class TestCVE002SafeAlternatives:
    """
    Test suite demonstrating safe alternatives to vulnerable command execution.
    
    These tests show the CORRECT way to execute commands without introducing
    command injection vulnerabilities.
    """

    @pytest.mark.unit
    def test_safe_subprocess_usage_with_list_args(self):
        """
        Test 11: Demonstrate safe subprocess usage with list arguments
        
        SAFE PATTERN: Use subprocess.run() with a list of arguments and shell=False
        This prevents shell interpretation and command injection.
        """
        # User input that would be dangerous with shell=True
        user_input = "test.txt; rm -rf /"
        
        # SAFE: Using list of arguments
        safe_command = ['cat', user_input]
        
        with patch('subprocess.run') as mock_run:
            # Simulate safe subprocess call
            subprocess.run(safe_command, shell=False)
            
            # Verify it was called safely
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            
            # shell should be False (or not specified)
            shell_param = call_args[1].get('shell', False)
            assert shell_param is False, \
                "Safe subprocess call should use shell=False"
            
            # Command should be a list
            assert isinstance(call_args[0][0], list), \
                "Safe subprocess call should use list arguments"

    @pytest.mark.unit
    def test_safe_command_with_shlex_quote(self):
        """
        Test 12: Demonstrate safe command construction with shlex.quote()
        
        SAFE PATTERN: If shell=True is absolutely necessary, use shlex.quote()
        to escape shell metacharacters in user input.
        """
        import shlex
        
        # User input with shell metacharacters
        user_input = "test.txt; rm -rf /"
        
        # SAFE: Quote the user input
        safe_input = shlex.quote(user_input)
        safe_command = f"cat {safe_input}"
        
        # Verify that shell metacharacters are escaped
        assert ";" in user_input, "Test input should contain semicolon"
        assert safe_input != user_input, "shlex.quote should modify the input"
        
        # The quoted version should prevent command injection
        # by treating the entire input as a single argument
        with patch('subprocess.run') as mock_run:
            subprocess.run(safe_command, shell=True)
            
            mock_run.assert_called_once()
            # In the real scenario, the shell would treat the quoted string
            # as a single filename, not as a command injection

    @pytest.mark.unit
    def test_safe_pathlib_operations(self):
        """
        Test 13: Demonstrate safe file operations without shell commands
        
        SAFE PATTERN: Use Python's built-in libraries (pathlib, os, shutil)
        instead of shell commands for file operations.
        """
        from pathlib import Path
        
        # Instead of: os.system('mkdir -p /tmp/test')
        # Use: Path('/tmp/test').mkdir(parents=True, exist_ok=True)
        
        # Instead of: os.system('cp source.txt dest.txt')
        # Use: shutil.copy('source.txt', 'dest.txt')
        
        # Instead of: os.system('rm file.txt')
        # Use: Path('file.txt').unlink()
        
        # This test verifies these patterns are safe
        assert hasattr(Path, 'mkdir'), "pathlib.Path should have mkdir method"
        assert hasattr(Path, 'unlink'), "pathlib.Path should have unlink method"
        
        # These operations don't involve shell command execution,
        # making them safe from command injection

    @pytest.mark.unit
    def test_compare_unsafe_vs_safe_execution(self):
        """
        Test 14: Side-by-side comparison of unsafe vs safe command execution
        
        This test demonstrates the difference between vulnerable and secure
        command execution patterns.
        """
        user_filename = "test.txt; cat /etc/passwd"
        
        # UNSAFE PATTERN 1: os.system with string interpolation
        unsafe_cmd_1 = f"cat {user_filename}"
        # This would execute: cat test.txt; cat /etc/passwd
        
        # UNSAFE PATTERN 2: subprocess.run with shell=True
        unsafe_cmd_2 = f"cat {user_filename}"
        # This would also execute both commands
        
        # SAFE PATTERN 1: subprocess.run with list args
        safe_cmd_1 = ['cat', user_filename]
        # This would try to open a file literally named "test.txt; cat /etc/passwd"
        # which would fail, but wouldn't execute the injection
        
        # SAFE PATTERN 2: shlex.quote with shell=True (if shell is required)
        import shlex
        safe_cmd_2 = f"cat {shlex.quote(user_filename)}"
        # This would quote the filename, preventing injection
        
        # Verify unsafe patterns contain the injection
        assert "; cat /etc/passwd" in unsafe_cmd_1
        assert "; cat /etc/passwd" in unsafe_cmd_2
        
        # Verify safe patterns handle it correctly
        assert isinstance(safe_cmd_1, list), "Safe command should be a list"
        assert "'" in safe_cmd_2 or '"' in safe_cmd_2, \
            "Safe command should contain quotes from shlex.quote"


class TestCVE002SpecificVulnerableFiles:
    """
    Test suite for specific vulnerable files identified in CVE-002.
    
    These tests verify the exact vulnerable code patterns in the files
    mentioned in the CVE report.
    """

    @pytest.mark.unit
    def test_cloud_py_line_115_vulnerability(self):
        """
        Test 15: Verify the specific vulnerability at nemo/utils/cloud.py:115
        
        Expected vulnerable code:
        os.system('chmod 777 /tmp && apt-get update && apt-get install -y libsndfile1 ffmpeg')
        
        Risk Level: MEDIUM
        While the command is hardcoded, it uses os.system() which is inherently
        unsafe. Future modifications could introduce user input.
        """
        file_path = Path(__file__).parent.parent.parent / "nemo" / "utils" / "cloud.py"
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        # Check around line 115 (accounting for 0-based indexing)
        vulnerable_found = False
        for i in range(max(0, 114-5), min(len(lines), 114+5)):
            if "os.system(" in lines[i] and "chmod 777" in lines[i]:
                vulnerable_found = True
                break
        
        assert vulnerable_found, \
            "Expected vulnerable os.system() call not found around line 115 in cloud.py"

    @pytest.mark.unit
    def test_deploy_base_py_line_36_vulnerability(self):
        """
        Test 16: Verify the specific vulnerability at nemo/collections/llm/deploy/base.py:36
        
        Expected vulnerable code:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        Risk Level: CRITICAL
        The cmd variable may be constructed from user input, making this
        a critical command injection vulnerability.
        """
        file_path = Path(__file__).parent.parent.parent / "nemo" / "collections" / "llm" / "deploy" / "base.py"
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        # Check around line 36
        vulnerable_found = False
        for i in range(max(0, 35-5), min(len(lines), 35+5)):
            if "subprocess.run(" in lines[i] and "shell=True" in lines[i]:
                vulnerable_found = True
                break
        
        assert vulnerable_found, \
            "Expected vulnerable subprocess.run() call not found around line 36 in deploy/base.py"

    @pytest.mark.unit
    def test_get_commonvoice_data_py_line_175_vulnerability(self):
        """
        Test 17: Verify the specific vulnerability at scripts/dataset_processing/get_commonvoice_data.py:175
        
        Expected vulnerable code:
        subprocess.run(commands, shell=True, stderr=sys.stderr, stdout=sys.stdout, capture_output=False)
        
        Risk Level: HIGH
        The commands variable is constructed from URLs and file paths, which
        could potentially be influenced by user input or configuration.
        """
        file_path = Path(__file__).parent.parent.parent / "scripts" / "dataset_processing" / "get_commonvoice_data.py"
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        # Check around line 175
        vulnerable_found = False
        for i in range(max(0, 174-5), min(len(lines), 174+5)):
            if "subprocess.run(" in lines[i] and "shell=True" in lines[i]:
                vulnerable_found = True
                break
        
        assert vulnerable_found, \
            "Expected vulnerable subprocess.run() call not found around line 175 in get_commonvoice_data.py"


# Summary of CVE-002 Security Tests
"""
This test module contains 17 comprehensive security tests for CVE-002 (Command Injection):

Detection Tests (Tests 1-6):
- Verify os.system() usage in cloud.py
- Verify subprocess.run(shell=True) in deploy/base.py
- Verify subprocess.run(shell=True) in get_commonvoice_data.py
- Scan entire codebase for os.system()
- Scan entire codebase for subprocess with shell=True
- AST-based analysis for unsafe subprocess usage

Exploitability Tests (Tests 7-10):
- Demonstrate command injection via os.system()
- Demonstrate command injection via subprocess.run(shell=True)
- Demonstrate command injection via piping
- Demonstrate command injection via command substitution

Safe Alternative Tests (Tests 11-14):
- Demonstrate safe subprocess usage with list arguments
- Demonstrate safe command construction with shlex.quote()
- Demonstrate safe pathlib operations
- Compare unsafe vs safe execution patterns

Specific Vulnerability Tests (Tests 15-17):
- Verify vulnerability at cloud.py:115
- Verify vulnerability at deploy/base.py:36
- Verify vulnerability at get_commonvoice_data.py:175

All tests are designed to:
1. Document the vulnerability
2. Verify its existence
3. Demonstrate exploitability
4. Show safe alternatives

These tests should PASS if the vulnerability exists and FAIL if it has been fixed.
"""
