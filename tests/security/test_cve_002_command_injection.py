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

This test suite verifies the presence of command injection vulnerabilities
in the NeMo codebase. These tests are designed to document the security
concerns and validate that the vulnerable patterns exist as described in
the CVE report.

CVE-002 Details:
- Title: Command Injection vulnerability
- Severity: CRITICAL
- Jira Issue: https://ml6team.atlassian.net/browse/DR-135

Vulnerability Description:
The application is vulnerable to command injection through unsafe use of:
1. os.system() with unsanitized input
2. subprocess.run() with shell=True and unsanitized input
3. subprocess.call() with shell=True and unsanitized input
4. os.popen() with unsanitized input

These tests verify the vulnerability exists and demonstrate both:
- Positive tests: Detecting vulnerable patterns in the codebase
- Negative tests: Demonstrating safe alternatives

NOTE: These tests are for SECURITY VERIFICATION ONLY and do NOT fix the vulnerabilities.
"""

import ast
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestCommandInjectionDetection:
    """Tests to detect command injection vulnerabilities in the codebase."""

    @pytest.mark.security
    @pytest.mark.unit
    def test_detect_os_system_in_cloud_utils(self):
        """
        Test CVE-002: Verify os.system() usage in nemo/utils/cloud.py
        
        This test verifies that nemo/utils/cloud.py contains a direct call to os.system()
        which is vulnerable to command injection. The specific vulnerable code is:
        
            os.system('chmod 777 /tmp && apt-get update && apt-get install -y libsndfile1 ffmpeg')
        
        Risk: While this specific command appears hardcoded, using os.system() is inherently
        dangerous as it executes commands through the shell, making it vulnerable to injection
        if any part of the command is derived from user input in the future.
        """
        file_path = Path("nemo/utils/cloud.py")
        assert file_path.exists(), f"File {file_path} not found"
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Verify os.system() is used
        assert 'os.system(' in content, "os.system() call not found in cloud.py"
        
        # Verify the specific vulnerable line exists
        assert 'os.system(\'chmod 777 /tmp && apt-get update && apt-get install -y libsndfile1 ffmpeg\')' in content, \
            "Expected vulnerable os.system() call not found"

    @pytest.mark.security
    @pytest.mark.unit
    def test_detect_subprocess_shell_true_in_deploy_base(self):
        """
        Test CVE-002: Verify subprocess.run() with shell=True in nemo/collections/llm/deploy/base.py
        
        This test verifies that the deploy base module uses subprocess.run() with shell=True,
        which is vulnerable to command injection when the cmd variable contains user input.
        
        The vulnerable pattern is:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        Risk: If 'cmd' is constructed from environment variables or user input without proper
        sanitization, attackers can inject arbitrary commands.
        """
        file_path = Path("nemo/collections/llm/deploy/base.py")
        assert file_path.exists(), f"File {file_path} not found"
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Verify subprocess.run with shell=True is used
        assert 'subprocess.run(' in content, "subprocess.run() not found"
        assert 'shell=True' in content, "shell=True not found in deploy/base.py"
        
        # Parse the AST to find subprocess.run calls with shell=True
        tree = ast.parse(content)
        found_vulnerable_pattern = False
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if (hasattr(node.func.value, 'id') and 
                        node.func.value.id == 'subprocess' and 
                        node.func.attr == 'run'):
                        # Check if shell=True is in the arguments
                        for keyword in node.keywords:
                            if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                                if keyword.value.value is True:
                                    found_vulnerable_pattern = True
                                    break
        
        assert found_vulnerable_pattern, "subprocess.run() with shell=True not found in AST analysis"

    @pytest.mark.security
    @pytest.mark.unit
    def test_detect_subprocess_shell_true_in_commonvoice_script(self):
        """
        Test CVE-002: Verify subprocess.run() with shell=True in get_commonvoice_data.py
        
        This test verifies that the CommonVoice data processing script uses subprocess.run()
        with shell=True where the command is constructed from user-provided arguments.
        
        The vulnerable pattern is:
            commands = " ".join([...])  # Command built from user input (args.language)
            subprocess.run(commands, shell=True, stderr=sys.stderr, stdout=sys.stdout, capture_output=False)
        
        Risk: The args.language parameter could be manipulated to inject arbitrary commands
        into the wget command being executed.
        """
        file_path = Path("scripts/dataset_processing/get_commonvoice_data.py")
        assert file_path.exists(), f"File {file_path} not found"
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Verify subprocess.run with shell=True is used
        assert 'subprocess.run(' in content, "subprocess.run() not found"
        assert 'shell=True' in content, "shell=True not found in get_commonvoice_data.py"
        
        # Verify command construction from args
        assert 'args.language' in content, "User input (args.language) not found"
        assert 'COMMON_VOICE_URL' in content, "URL construction not found"

    @pytest.mark.security
    @pytest.mark.unit
    def test_detect_os_system_in_hf_text_data_script(self):
        """
        Test CVE-002: Verify os.system() usage in get_hf_text_data.py
        
        This test verifies that the HuggingFace text data script uses os.system()
        with an f-string that includes user-controlled config value.
        
        The vulnerable pattern is:
            os.system(f"rm {cfg.output_file}")
        
        Risk: If cfg.output_file contains shell metacharacters or command injection
        payloads, arbitrary commands can be executed.
        """
        file_path = Path("scripts/tokenizers/get_hf_text_data.py")
        assert file_path.exists(), f"File {file_path} not found"
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Verify os.system() is used
        assert 'os.system(' in content, "os.system() call not found"
        
        # Verify it's used with an f-string containing cfg variable
        assert 'os.system(f"rm {cfg.output_file}")' in content, \
            "Expected vulnerable os.system() call with f-string not found"

    @pytest.mark.security
    @pytest.mark.unit
    def test_detect_subprocess_shell_true_in_aishell3_script(self):
        """
        Test CVE-002: Verify subprocess.run() with shell=True in aishell3 data script
        
        This test verifies that the AISHELL3 data processing script uses subprocess.run()
        and subprocess.check_output() with shell=True.
        
        The vulnerable patterns are:
            subprocess.check_output(f"soxi -D {wav_file}", shell=True)
            subprocess.run(f"sox {wav_file} -r 22050 -c 1 -b 16 {processed_file}", shell=True)
        
        Risk: If wav_file or processed_file paths contain shell metacharacters,
        arbitrary commands can be injected.
        """
        file_path = Path("scripts/dataset_processing/tts/aishell3/get_data.py")
        assert file_path.exists(), f"File {file_path} not found"
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Verify subprocess calls with shell=True
        assert 'subprocess.check_output(' in content, "subprocess.check_output() not found"
        assert 'subprocess.run(' in content, "subprocess.run() not found"
        assert 'shell=True' in content, "shell=True not found"
        
        # Verify the specific vulnerable patterns
        assert 'soxi -D' in content, "soxi command not found"
        assert 'sox {wav_file}' in content or 'sox' in content, "sox command pattern not found"


class TestCommandInjectionVulnerabilityDemonstration:
    """Tests that demonstrate how the command injection vulnerabilities can be exploited."""

    @pytest.mark.security
    @pytest.mark.unit
    def test_os_system_command_injection_vulnerability(self):
        """
        Test CVE-002: Demonstrate os.system() command injection vulnerability
        
        This test demonstrates how os.system() can be exploited when user input
        is incorporated into the command string without sanitization.
        
        Example vulnerable code:
            filename = user_input  # e.g., "file.txt; malicious_command"
            os.system(f"rm {filename}")
        
        This would execute both 'rm file.txt' and 'malicious_command'.
        """
        # Create a test scenario showing the vulnerability
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_file = os.path.join(tmpdir, "safe.txt")
            proof_file = os.path.join(tmpdir, "proof_of_injection.txt")
            
            # Create safe file
            Path(safe_file).touch()
            assert os.path.exists(safe_file)
            
            # Simulate malicious user input with command injection
            malicious_input = f"{safe_file}; touch {proof_file}"
            
            # This demonstrates the vulnerability - DO NOT USE IN PRODUCTION
            # We use a controlled environment to prove the vulnerability exists
            try:
                os.system(f"rm {malicious_input}")
            except Exception:
                pass  # May fail on rm, but injection should still execute
            
            # Verify the injected command was executed
            assert os.path.exists(proof_file), \
                "Command injection succeeded - proof file was created by injected command"

    @pytest.mark.security
    @pytest.mark.unit
    def test_subprocess_shell_true_command_injection_vulnerability(self):
        """
        Test CVE-002: Demonstrate subprocess.run() with shell=True command injection
        
        This test demonstrates how subprocess.run() with shell=True can be exploited
        when user input is incorporated into the command.
        
        Example vulnerable code:
            user_file = user_input  # e.g., "file.txt && malicious_command"
            subprocess.run(f"cat {user_file}", shell=True)
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            proof_file = os.path.join(tmpdir, "injection_proof.txt")
            
            # Simulate malicious user input
            malicious_input = f"nonexistent && touch {proof_file}"
            
            # This demonstrates the vulnerability - DO NOT USE IN PRODUCTION
            try:
                subprocess.run(f"cat {malicious_input}", shell=True, capture_output=True)
            except Exception:
                pass  # cat may fail, but injection should still execute
            
            # Verify the injected command was executed
            assert os.path.exists(proof_file), \
                "Command injection succeeded - proof file was created by injected command"

    @pytest.mark.security
    @pytest.mark.unit
    def test_shell_metacharacter_exploitation(self):
        """
        Test CVE-002: Demonstrate exploitation via shell metacharacters
        
        This test shows various shell metacharacters that can be used for injection:
        - ; (semicolon) - command separator
        - && (double ampersand) - conditional execution
        - || (double pipe) - alternative execution
        - | (pipe) - output redirection
        - ` (backtick) - command substitution
        - $() - command substitution
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test various injection vectors
            injection_vectors = [
                ("semicolon", f"dummy; touch {tmpdir}/semicolon.txt"),
                ("ampersand", f"false && touch {tmpdir}/ampersand.txt || touch {tmpdir}/ampersand.txt"),
                ("pipe", f"echo test | tee {tmpdir}/pipe.txt"),
            ]
            
            for vector_name, malicious_cmd in injection_vectors:
                try:
                    # Demonstrate the vulnerability
                    subprocess.run(malicious_cmd, shell=True, capture_output=True)
                except Exception:
                    pass
            
            # Verify at least some injection vectors succeeded
            files_created = list(Path(tmpdir).glob("*.txt"))
            assert len(files_created) > 0, \
                f"Shell metacharacter injection succeeded - {len(files_created)} proof files created"


class TestSafeAlternativesToCommandInjection:
    """Tests demonstrating safe alternatives to vulnerable command execution patterns."""

    @pytest.mark.security
    @pytest.mark.unit
    def test_safe_subprocess_without_shell(self):
        """
        Test CVE-002: Demonstrate safe subprocess usage without shell=True
        
        Safe alternative:
            # UNSAFE: subprocess.run(f"cat {filename}", shell=True)
            # SAFE: subprocess.run(["cat", filename], shell=False)
        
        When shell=False (default), arguments are passed directly to the program
        without shell interpretation, preventing command injection.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.txt")
            Path(test_file).write_text("safe content")
            
            # Try to inject a command - this will FAIL with shell=False (safe)
            malicious_input = f"{test_file}; echo 'injected' > {tmpdir}/proof.txt"
            
            # Safe approach - shell=False prevents injection
            result = subprocess.run(
                ["cat", malicious_input],  # Treated as literal filename
                shell=False,  # Safe: no shell interpretation
                capture_output=True,
                text=True
            )
            
            # The injection should NOT succeed because malicious_input is treated
            # as a literal filename (which doesn't exist), not as a command
            assert not os.path.exists(f"{tmpdir}/proof.txt"), \
                "Injection was prevented - proof file was NOT created (safe behavior)"
            assert result.returncode != 0, "Command failed as expected (file doesn't exist)"

    @pytest.mark.security
    @pytest.mark.unit
    def test_safe_path_operations_instead_of_os_system(self):
        """
        Test CVE-002: Demonstrate safe file operations instead of os.system()
        
        Safe alternative:
            # UNSAFE: os.system(f"rm {filename}")
            # SAFE: Path(filename).unlink()
        
        Use Python's built-in file operations instead of shell commands.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.txt")
            Path(test_file).touch()
            assert os.path.exists(test_file)
            
            # Safe approach using pathlib
            Path(test_file).unlink()
            assert not os.path.exists(test_file), "File deleted safely without shell"
            
            # Even with malicious input, pathlib operations are safe
            malicious_name = "test.txt; touch injected.txt"
            malicious_file = os.path.join(tmpdir, malicious_name)
            Path(malicious_file).touch()  # Creates file with literal name
            
            # Verify the file was created with the literal name (including semicolon)
            assert os.path.exists(malicious_file), "File created with literal name (safe)"
            
            # Verify no command injection occurred
            assert not os.path.exists(os.path.join(tmpdir, "injected.txt")), \
                "No command injection - 'injected.txt' was not created (safe behavior)"

    @pytest.mark.security
    @pytest.mark.unit
    def test_safe_shlex_quote_usage(self):
        """
        Test CVE-002: Demonstrate shlex.quote() for safe shell argument escaping
        
        If shell=True is absolutely necessary, use shlex.quote() to escape arguments:
            # UNSAFE: subprocess.run(f"cat {filename}", shell=True)
            # SAFER: subprocess.run(f"cat {shlex.quote(filename)}", shell=True)
        
        Note: Avoiding shell=True entirely is still the recommended approach.
        """
        import shlex
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            safe_file = os.path.join(tmpdir, "test.txt")
            Path(safe_file).write_text("content")
            
            # Malicious input that would inject a command
            malicious_input = f"{safe_file}; touch {tmpdir}/proof.txt"
            
            # Using shlex.quote() to safely escape the argument
            escaped_input = shlex.quote(malicious_input)
            
            # Even with shell=True, the escaped input is safe
            result = subprocess.run(
                f"cat {escaped_input}",  # The entire string is treated as one filename
                shell=True,
                capture_output=True,
                text=True
            )
            
            # Verify no command injection occurred
            assert not os.path.exists(f"{tmpdir}/proof.txt"), \
                "shlex.quote() prevented injection - proof file was NOT created (safe behavior)"
            
            # The command should fail because the escaped filename doesn't exist
            assert result.returncode != 0, "Command failed as expected (escaped filename doesn't exist)"

    @pytest.mark.security
    @pytest.mark.unit
    def test_safe_input_validation_and_sanitization(self):
        """
        Test CVE-002: Demonstrate input validation and sanitization
        
        Best practices for preventing command injection:
        1. Validate input against allowlists (e.g., allowed characters, patterns)
        2. Reject input containing shell metacharacters
        3. Use parameterized commands instead of string interpolation
        """
        import re
        
        def is_safe_filename(filename):
            """Validate filename contains only safe characters."""
            # Allow only alphanumeric, underscore, hyphen, and dot
            return bool(re.match(r'^[a-zA-Z0-9._-]+$', filename))
        
        # Test cases
        safe_filenames = ["test.txt", "data_file.csv", "output-1.json"]
        unsafe_filenames = ["test; rm -rf /", "file && malicious", "data|evil"]
        
        # Verify safe filenames pass validation
        for filename in safe_filenames:
            assert is_safe_filename(filename), f"{filename} should be considered safe"
        
        # Verify unsafe filenames are rejected
        for filename in unsafe_filenames:
            assert not is_safe_filename(filename), f"{filename} should be rejected (contains metacharacters)"
        
        # Demonstrate usage
        with tempfile.TemporaryDirectory() as tmpdir:
            user_input = "test; touch injected.txt"  # Malicious input
            
            if is_safe_filename(user_input):
                # Would execute command
                pass
            else:
                # Input validation prevents the vulnerable code from executing
                assert True, "Malicious input rejected by validation (safe behavior)"


class TestVulnerableCodePatternDetection:
    """Tests to detect vulnerable code patterns across the entire codebase."""

    @pytest.mark.security
    @pytest.mark.unit
    def test_scan_for_os_system_usage(self):
        """
        Test CVE-002: Scan codebase for os.system() usage
        
        This test scans the codebase to identify all instances of os.system()
        which are potential command injection vulnerabilities.
        """
        # List of files known to contain os.system()
        known_vulnerable_files = [
            "nemo/utils/cloud.py",
            "scripts/tokenizers/get_hf_text_data.py",
            "scripts/installers/setup_os2s_decoders.py",
            "scripts/dataset_processing/speaker_tasks/get_ami_data.py",
            "scripts/dataset_processing/spoken_wikipedia/preprocess.py",
        ]
        
        vulnerable_files_found = []
        
        for file_path_str in known_vulnerable_files:
            file_path = Path(file_path_str)
            if file_path.exists():
                with open(file_path, 'r') as f:
                    content = f.read()
                    if 'os.system(' in content:
                        vulnerable_files_found.append(str(file_path))
        
        assert len(vulnerable_files_found) > 0, \
            f"Found {len(vulnerable_files_found)} files using os.system(): {vulnerable_files_found}"

    @pytest.mark.security
    @pytest.mark.unit
    def test_scan_for_subprocess_shell_true_usage(self):
        """
        Test CVE-002: Scan codebase for subprocess with shell=True
        
        This test scans the codebase to identify all instances of subprocess
        calls with shell=True, which are potential command injection vulnerabilities.
        """
        # List of files known to contain subprocess with shell=True
        known_vulnerable_files = [
            "nemo/collections/llm/deploy/base.py",
            "scripts/dataset_processing/get_commonvoice_data.py",
            "scripts/dataset_processing/tts/aishell3/get_data.py",
        ]
        
        vulnerable_files_found = []
        
        for file_path_str in known_vulnerable_files:
            file_path = Path(file_path_str)
            if file_path.exists():
                with open(file_path, 'r') as f:
                    content = f.read()
                    if 'shell=True' in content and ('subprocess.run' in content or 
                                                     'subprocess.call' in content or 
                                                     'subprocess.check_output' in content):
                        vulnerable_files_found.append(str(file_path))
        
        assert len(vulnerable_files_found) > 0, \
            f"Found {len(vulnerable_files_found)} files using subprocess with shell=True: {vulnerable_files_found}"

    @pytest.mark.security
    @pytest.mark.unit
    def test_verify_no_input_sanitization_in_vulnerable_code(self):
        """
        Test CVE-002: Verify lack of input sanitization in vulnerable code
        
        This test verifies that the vulnerable code does not use proper sanitization
        functions like shlex.quote() to protect against command injection.
        """
        file_path = Path("scripts/tokenizers/get_hf_text_data.py")
        
        if file_path.exists():
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Check for vulnerable os.system() call
            assert 'os.system(f"rm {cfg.output_file}")' in content, \
                "Vulnerable os.system() pattern found"
            
            # Verify no sanitization is used
            assert 'shlex.quote' not in content, \
                "No shlex.quote() sanitization found (vulnerability confirmed)"
            assert 'shlex.split' not in content, \
                "No shlex.split() sanitization found (vulnerability confirmed)"


class TestCommandInjectionRiskAssessment:
    """Tests to assess the risk and impact of command injection vulnerabilities."""

    @pytest.mark.security
    @pytest.mark.unit
    def test_assess_cloud_utils_risk(self):
        """
        Test CVE-002: Assess risk in nemo/utils/cloud.py
        
        Risk Assessment:
        - File: nemo/utils/cloud.py
        - Vulnerable Code: os.system('chmod 777 /tmp && apt-get update && apt-get install -y libsndfile1 ffmpeg')
        - Risk Level: MEDIUM (currently hardcoded, but sets bad precedent)
        - Impact: While currently hardcoded, using os.system() creates risk if code is modified
        - Recommendation: Replace with subprocess calls without shell=True
        """
        file_path = Path("nemo/utils/cloud.py")
        assert file_path.exists()
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Document the risk
        risk_assessment = {
            "file": str(file_path),
            "vulnerable_function": "os.system()",
            "risk_level": "MEDIUM",
            "reason": "Hardcoded command, but using os.system() is inherently risky",
            "line_contains": "os.system('chmod 777 /tmp",
        }
        
        assert 'os.system(' in content, f"Risk confirmed: {risk_assessment}"

    @pytest.mark.security
    @pytest.mark.unit
    def test_assess_deploy_base_risk(self):
        """
        Test CVE-002: Assess risk in nemo/collections/llm/deploy/base.py
        
        Risk Assessment:
        - File: nemo/collections/llm/deploy/base.py
        - Vulnerable Code: subprocess.run(cmd, shell=True, ...)
        - Risk Level: HIGH (cmd constructed from environment variables)
        - Impact: Environment variables can be controlled by users/attackers
        - Recommendation: Use subprocess without shell=True with argument lists
        """
        file_path = Path("nemo/collections/llm/deploy/base.py")
        assert file_path.exists()
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        risk_assessment = {
            "file": str(file_path),
            "vulnerable_function": "subprocess.run()",
            "risk_level": "HIGH",
            "reason": "Command constructed from environment variables with shell=True",
            "contains_pattern": "shell=True",
        }
        
        assert 'shell=True' in content, f"Risk confirmed: {risk_assessment}"

    @pytest.mark.security
    @pytest.mark.unit
    def test_assess_data_processing_scripts_risk(self):
        """
        Test CVE-002: Assess risk in data processing scripts
        
        Risk Assessment:
        - Files: get_commonvoice_data.py, get_data.py (aishell3)
        - Vulnerable Code: subprocess.run() with shell=True and user input
        - Risk Level: CRITICAL (user-provided arguments directly used in commands)
        - Impact: Attackers can inject arbitrary commands via script arguments
        - Recommendation: Use subprocess without shell=True, validate all inputs
        """
        vulnerable_scripts = [
            "scripts/dataset_processing/get_commonvoice_data.py",
            "scripts/dataset_processing/tts/aishell3/get_data.py",
        ]
        
        high_risk_files = []
        
        for script_path_str in vulnerable_scripts:
            script_path = Path(script_path_str)
            if script_path.exists():
                with open(script_path, 'r') as f:
                    content = f.read()
                
                # Check for the dangerous combination
                if 'shell=True' in content and 'argparse' in content:
                    high_risk_files.append(str(script_path))
        
        assert len(high_risk_files) > 0, \
            f"CRITICAL RISK: {len(high_risk_files)} scripts use shell=True with user input: {high_risk_files}"
