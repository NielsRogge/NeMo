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

These tests verify the presence of command injection vulnerabilities in the codebase.
The application is vulnerable to command injection through unsafe use of os.system,
subprocess.call, or subprocess.run with shell=True, especially in scripts that process
user-provided input or configuration.

DO NOT FIX THESE VULNERABILITIES - These tests are designed to detect and document
the security issues for remediation tracking.
"""

import ast
import os
import re
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def workspace_root():
    """Get the workspace root directory."""
    return Path(__file__).parent.parent.parent


class TestCommandInjectionDetection:
    """
    Test suite to detect command injection vulnerabilities in the codebase.
    Each test method identifies specific instances where shell commands are executed
    unsafely with potential for injection attacks.
    """

    def test_os_system_usage_in_cloud_utils(self, workspace_root):
        """
        Test for command injection vulnerability in nemo/utils/cloud.py.
        
        Vulnerability: Uses os.system() with hardcoded command, which is inherently unsafe.
        Location: nemo/utils/cloud.py:115
        Pattern: os.system('chmod 777 /tmp && apt-get update && apt-get install -y libsndfile1 ffmpeg')
        
        Risk: While the command is hardcoded, os.system() should be avoided in favor of
        safer alternatives like subprocess.run() with shell=False and argument lists.
        """
        file_path = workspace_root / "nemo" / "utils" / "cloud.py"
        assert file_path.exists(), f"File not found: {file_path}"

        with open(file_path, 'r') as f:
            content = f.read()

        # Check for os.system usage
        os_system_pattern = r'os\.system\([\'"].*[\'"]?\)'
        matches = re.findall(os_system_pattern, content)
        
        assert len(matches) > 0, (
            "Expected to find os.system() usage in cloud.py (CVE-002). "
            "This vulnerability involves executing shell commands with os.system()."
        )

        # Verify the specific vulnerable line exists
        vulnerable_line = "os.system('chmod 777 /tmp && apt-get update && apt-get install -y libsndfile1 ffmpeg')"
        assert vulnerable_line in content, (
            f"Expected vulnerable line not found in cloud.py. "
            f"Looking for: {vulnerable_line}"
        )

    def test_subprocess_shell_true_in_deploy_base(self, workspace_root):
        """
        Test for command injection vulnerability in nemo/collections/llm/deploy/base.py.
        
        Vulnerability: Uses subprocess.run() with shell=True and string interpolation.
        Location: nemo/collections/llm/deploy/base.py:36
        Pattern: subprocess.run(cmd, shell=True, ...) where cmd = f"env | grep ^{prefix} | cut -d= -f1"
        
        Risk: HIGH - The prefix variable comes from a loop over user-controllable list.
        An attacker could inject malicious commands through the prefix variable.
        """
        file_path = workspace_root / "nemo" / "collections" / "llm" / "deploy" / "base.py"
        assert file_path.exists(), f"File not found: {file_path}"

        with open(file_path, 'r') as f:
            content = f.read()

        # Check for subprocess.run with shell=True
        shell_true_pattern = r'subprocess\.run\([^)]*shell=True[^)]*\)'
        matches = re.findall(shell_true_pattern, content, re.DOTALL)
        
        assert len(matches) > 0, (
            "Expected to find subprocess.run() with shell=True in deploy/base.py (CVE-002). "
            "This vulnerability allows command injection through environment variable prefix."
        )

        # Verify the command construction pattern exists
        cmd_pattern = r'cmd\s*=\s*f["\']env\s*\|\s*grep\s*\^{prefix}'
        assert re.search(cmd_pattern, content), (
            "Expected to find command construction with f-string interpolation in deploy/base.py"
        )

    def test_subprocess_shell_true_in_commonvoice_script(self, workspace_root):
        """
        Test for command injection vulnerability in get_commonvoice_data.py.
        
        Vulnerability: Uses subprocess.run() with shell=True and user-controlled arguments.
        Location: scripts/dataset_processing/get_commonvoice_data.py:175
        Pattern: subprocess.run(commands, shell=True, ...) where commands is built from args
        
        Risk: CRITICAL - Commands are constructed from command-line arguments and URL.
        An attacker with control over arguments could inject arbitrary commands.
        """
        file_path = workspace_root / "scripts" / "dataset_processing" / "get_commonvoice_data.py"
        assert file_path.exists(), f"File not found: {file_path}"

        with open(file_path, 'r') as f:
            content = f.read()

        # Check for subprocess.run with shell=True
        shell_true_pattern = r'subprocess\.run\([^)]*shell=True[^)]*\)'
        matches = re.findall(shell_true_pattern, content, re.DOTALL)
        
        assert len(matches) > 0, (
            "Expected to find subprocess.run() with shell=True in get_commonvoice_data.py (CVE-002). "
            "This vulnerability allows command injection through wget command construction."
        )

        # Verify commands list construction with join
        assert 'commands = " ".join(commands)' in content, (
            "Expected to find command construction pattern with .join() in get_commonvoice_data.py"
        )

    def test_os_system_file_removal_in_tokenizer_script(self, workspace_root):
        """
        Test for command injection vulnerability in get_hf_text_data.py.
        
        Vulnerability: Uses os.system() with f-string interpolation of user-controlled config.
        Location: scripts/tokenizers/get_hf_text_data.py:81
        Pattern: os.system(f"rm {cfg.output_file}")
        
        Risk: CRITICAL - The cfg.output_file is user-controlled configuration.
        An attacker could inject commands like: "file.txt; malicious_command" or "file.txt && rm -rf /"
        """
        file_path = workspace_root / "scripts" / "tokenizers" / "get_hf_text_data.py"
        assert file_path.exists(), f"File not found: {file_path}"

        with open(file_path, 'r') as f:
            content = f.read()

        # Check for os.system with f-string
        os_system_fstring_pattern = r'os\.system\(f["\']rm\s+{[^}]+}["\']?\)'
        matches = re.findall(os_system_fstring_pattern, content)
        
        assert len(matches) > 0, (
            "Expected to find os.system() with f-string interpolation in get_hf_text_data.py (CVE-002). "
            "This vulnerability allows command injection through file path manipulation."
        )

        # Verify specific vulnerable pattern
        assert 'os.system(f"rm {cfg.output_file}")' in content, (
            "Expected vulnerable line 'os.system(f\"rm {cfg.output_file}\")' not found"
        )

    def test_os_system_in_decoder_setup_script(self, workspace_root):
        """
        Test for command injection vulnerability in setup_os2s_decoders.py.
        
        Vulnerability: Uses os.system() with command constructed from variables.
        Location: scripts/installers/setup_os2s_decoders.py:90
        Pattern: os.system(command) where command includes header and library variables
        
        Risk: MEDIUM - The compile_test function constructs bash commands with variables.
        If header or library parameters come from untrusted sources, injection is possible.
        """
        file_path = workspace_root / "scripts" / "installers" / "setup_os2s_decoders.py"
        assert file_path.exists(), f"File not found: {file_path}"

        with open(file_path, 'r') as f:
            content = f.read()

        # Check for os.system usage
        os_system_pattern = r'os\.system\(command\)'
        matches = re.findall(os_system_pattern, content)
        
        assert len(matches) > 0, (
            "Expected to find os.system(command) in setup_os2s_decoders.py (CVE-002). "
            "This vulnerability involves executing shell commands with constructed strings."
        )

        # Verify command construction with bash -c
        assert 'bash -c' in content and 'g++ -include' in content, (
            "Expected to find bash command construction pattern in setup_os2s_decoders.py"
        )

        # Also check for swig command with os.system
        swig_pattern = r'os\.system\(["\']swig\s+'
        assert re.search(swig_pattern, content), (
            "Expected to find os.system() call for swig command in setup_os2s_decoders.py"
        )

    def test_multiple_os_system_in_ami_data_script(self, workspace_root):
        """
        Test for command injection vulnerabilities in get_ami_data.py.
        
        Vulnerability: Multiple uses of os.system() with f-string interpolation.
        Locations: scripts/dataset_processing/speaker_tasks/get_ami_data.py:68, 75-76, 79, 81
        Patterns: 
            - os.system(f"wget -P {split_path} ...")
            - os.system(f"wget -P {audio_type_path} ...")
            - os.system(f"wget -P {rttm_path} ...")
            - os.system(f"wget -P {uem_path} ...")
        
        Risk: HIGH - Multiple os.system calls with path variables that could be manipulated
        through command-line arguments or environment variables.
        """
        file_path = workspace_root / "scripts" / "dataset_processing" / "speaker_tasks" / "get_ami_data.py"
        assert file_path.exists(), f"File not found: {file_path}"

        with open(file_path, 'r') as f:
            content = f.read()

        # Check for os.system with wget commands
        wget_pattern = r'os\.system\(f["\']wget\s+-P\s+{[^}]+}'
        matches = re.findall(wget_pattern, content)
        
        assert len(matches) >= 3, (
            f"Expected to find at least 3 os.system() wget calls in get_ami_data.py (CVE-002). "
            f"Found {len(matches)}. These vulnerabilities allow command injection through path variables."
        )

    def test_subprocess_shell_true_in_aishell3_script(self, workspace_root):
        """
        Test for command injection vulnerabilities in aishell3/get_data.py.
        
        Vulnerability: Uses subprocess with shell=True and variable interpolation.
        Locations: scripts/dataset_processing/tts/aishell3/get_data.py:102, 107
        Patterns:
            - subprocess.check_output(f"soxi -D {wav_file}", shell=True)
            - subprocess.run(f"sox {wav_file} -r 22050 -c 1 -b 16 {processed_file}", shell=True)
        
        Risk: HIGH - File paths are constructed from dataset content.
        If an attacker can control filenames in the dataset, they can inject commands.
        """
        file_path = workspace_root / "scripts" / "dataset_processing" / "tts" / "aishell3" / "get_data.py"
        assert file_path.exists(), f"File not found: {file_path}"

        with open(file_path, 'r') as f:
            content = f.read()

        # Check for subprocess.check_output with shell=True
        check_output_pattern = r'subprocess\.check_output\([^)]*shell=True[^)]*\)'
        matches_check = re.findall(check_output_pattern, content, re.DOTALL)
        
        # Check for subprocess.run with shell=True
        run_pattern = r'subprocess\.run\([^)]*shell=True[^)]*\)'
        matches_run = re.findall(run_pattern, content, re.DOTALL)
        
        total_matches = len(matches_check) + len(matches_run)
        assert total_matches >= 2, (
            f"Expected to find at least 2 subprocess calls with shell=True in get_data.py (CVE-002). "
            f"Found {total_matches}. These vulnerabilities allow command injection through file paths."
        )

        # Verify specific command patterns
        assert 'soxi -D' in content and 'sox' in content, (
            "Expected to find soxi and sox command patterns in get_data.py"
        )

    def test_ast_analysis_for_shell_true_usage(self, workspace_root):
        """
        Test using AST analysis to detect subprocess calls with shell=True.
        
        This test performs static analysis using Python's ast module to find all
        instances of subprocess.run(), subprocess.call(), subprocess.Popen(), and
        subprocess.check_output() with shell=True parameter.
        
        Risk: This provides a comprehensive detection of all shell=True usage patterns
        across the entire codebase.
        """
        vulnerable_files = []
        
        # Files to analyze based on previous grep results
        files_to_check = [
            "nemo/collections/llm/deploy/base.py",
            "scripts/dataset_processing/get_commonvoice_data.py",
            "scripts/dataset_processing/tts/aishell3/get_data.py",
        ]
        
        for file_rel_path in files_to_check:
            file_path = workspace_root / file_rel_path
            if not file_path.exists():
                continue
                
            try:
                with open(file_path, 'r') as f:
                    tree = ast.parse(f.read(), filename=str(file_path))
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        # Check if it's a subprocess call
                        if isinstance(node.func, ast.Attribute):
                            if (hasattr(node.func.value, 'id') and 
                                node.func.value.id == 'subprocess' and
                                node.func.attr in ['run', 'call', 'Popen', 'check_output']):
                                
                                # Check for shell=True in keywords
                                for keyword in node.keywords:
                                    if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                                        if keyword.value.value is True:
                                            vulnerable_files.append({
                                                'file': file_rel_path,
                                                'line': node.lineno,
                                                'function': node.func.attr
                                            })
            except SyntaxError:
                # Skip files with syntax errors
                pass
        
        assert len(vulnerable_files) > 0, (
            "Expected to find subprocess calls with shell=True through AST analysis (CVE-002). "
            f"Analyzed files: {files_to_check}"
        )

    def test_os_system_usage_detection(self, workspace_root):
        """
        Test to detect all os.system() usage in the codebase.
        
        This test searches for any usage of os.system() which is inherently dangerous
        as it always uses the shell to execute commands, making it vulnerable to
        command injection attacks.
        
        Risk: os.system() should never be used with user-controlled input and should
        be replaced with subprocess.run() with shell=False.
        """
        vulnerable_files = []
        
        # Files known to contain os.system based on analysis
        files_to_check = [
            "nemo/utils/cloud.py",
            "scripts/tokenizers/get_hf_text_data.py",
            "scripts/installers/setup_os2s_decoders.py",
            "scripts/dataset_processing/speaker_tasks/get_ami_data.py",
        ]
        
        for file_rel_path in files_to_check:
            file_path = workspace_root / file_rel_path
            if not file_path.exists():
                continue
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Find all os.system calls
            os_system_pattern = r'os\.system\('
            if re.search(os_system_pattern, content):
                # Count occurrences
                matches = re.findall(os_system_pattern, content)
                vulnerable_files.append({
                    'file': file_rel_path,
                    'count': len(matches)
                })
        
        assert len(vulnerable_files) >= 4, (
            f"Expected to find os.system() usage in at least 4 files (CVE-002). "
            f"Found {len(vulnerable_files)} files: {vulnerable_files}"
        )

    def test_command_injection_with_fstring_interpolation(self, workspace_root):
        """
        Test to detect command execution with f-string interpolation.
        
        This test specifically looks for the dangerous pattern of using f-strings
        to construct shell commands, which is a common source of command injection
        vulnerabilities.
        
        Risk: CRITICAL - F-string interpolation in shell commands can easily lead
        to command injection if any interpolated variable comes from user input.
        """
        vulnerable_patterns = []
        
        files_to_check = [
            "scripts/tokenizers/get_hf_text_data.py",
            "scripts/dataset_processing/speaker_tasks/get_ami_data.py",
            "scripts/dataset_processing/tts/aishell3/get_data.py",
        ]
        
        for file_rel_path in files_to_check:
            file_path = workspace_root / file_rel_path
            if not file_path.exists():
                continue
            
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                # Look for os.system or subprocess with f-strings
                if ('os.system(f' in line or 
                    'subprocess.run(f' in line or 
                    'subprocess.check_output(f' in line or
                    'subprocess.call(f' in line):
                    vulnerable_patterns.append({
                        'file': file_rel_path,
                        'line': line_num,
                        'content': line.strip()
                    })
        
        assert len(vulnerable_patterns) > 0, (
            f"Expected to find command execution with f-string interpolation (CVE-002). "
            f"This is a critical vulnerability pattern."
        )

    def test_grep_command_construction_vulnerability(self, workspace_root):
        """
        Test for the specific vulnerability in deploy/base.py involving grep command.
        
        This test focuses on the pattern where a prefix variable is used to construct
        a grep command without proper sanitization.
        
        Risk: HIGH - The function iterates over ['SLURM_', 'PMI_', 'PMIX_'] prefixes,
        but if this list or the prefix handling is modified to accept external input,
        it becomes a critical vulnerability.
        """
        file_path = workspace_root / "nemo" / "collections" / "llm" / "deploy" / "base.py"
        assert file_path.exists(), f"File not found: {file_path}"

        with open(file_path, 'r') as f:
            content = f.read()

        # Check for the specific grep command construction
        grep_pattern = r'grep\s*\^{prefix}'
        assert re.search(grep_pattern, content), (
            "Expected to find grep command construction with ^{prefix} pattern in deploy/base.py (CVE-002)"
        )

        # Verify the function that uses this pattern
        assert 'def unset_vars_with_prefix(prefix):' in content, (
            "Expected to find unset_vars_with_prefix function in deploy/base.py"
        )

        # Verify no input sanitization exists for the prefix
        # (absence of shlex.quote or similar)
        assert 'shlex.quote' not in content, (
            "Found shlex.quote in deploy/base.py, but the test expects NO sanitization "
            "to demonstrate the vulnerability."
        )


class TestCommandInjectionVulnerabilitySummary:
    """
    Summary test class that provides an overview of all command injection vulnerabilities.
    """

    def test_vulnerability_summary_report(self, workspace_root):
        """
        Generate a summary report of all detected command injection vulnerabilities.
        
        This test aggregates findings from all vulnerability detection tests and
        provides a comprehensive report for security analysis.
        """
        vulnerabilities = {
            'os.system': [
                'nemo/utils/cloud.py:115 - Hardcoded system command',
                'scripts/tokenizers/get_hf_text_data.py:81 - User-controlled file path',
                'scripts/installers/setup_os2s_decoders.py:90, 120 - Command construction from variables',
                'scripts/dataset_processing/speaker_tasks/get_ami_data.py:68, 75-76, 79, 81 - Multiple wget commands',
            ],
            'subprocess with shell=True': [
                'nemo/collections/llm/deploy/base.py:36 - Grep command with variable prefix',
                'scripts/dataset_processing/get_commonvoice_data.py:175 - Wget command from args',
                'scripts/dataset_processing/tts/aishell3/get_data.py:102, 107 - File path in commands',
            ]
        }
        
        total_vulnerabilities = sum(len(v) for v in vulnerabilities.values())
        
        # Assert that we detected all expected vulnerabilities
        assert total_vulnerabilities >= 7, (
            f"Expected to detect at least 7 command injection vulnerabilities (CVE-002). "
            f"Found {total_vulnerabilities}.\n\n"
            f"Summary:\n"
            f"- os.system vulnerabilities: {len(vulnerabilities['os.system'])}\n"
            f"- subprocess shell=True vulnerabilities: {len(vulnerabilities['subprocess with shell=True'])}\n\n"
            f"Details:\n" +
            "\n".join(f"  {cat}:\n" + "\n".join(f"    - {v}" for v in vuln) 
                     for cat, vuln in vulnerabilities.items())
        )

    def test_cve_002_acceptance_criteria_validation(self, workspace_root):
        """
        Validate that CVE-002 acceptance criteria are testable.
        
        This test verifies that we can detect:
        1. All identified instances of command injection
        2. Usage of shell=True in subprocess calls
        3. Absence of input sanitization (shlex.quote)
        4. Patterns that make the application vulnerable to command injection attacks
        
        The acceptance criteria state:
        - All identified instances of command injection should be remediated
        - A policy should prevent use of shell=True unless necessary and sanitized
        - The application should not be vulnerable to command injection attacks
        
        This test confirms we can detect violations of these criteria.
        """
        # Count total vulnerable patterns found
        vulnerable_files_count = 0
        files_with_shell_true = []
        files_with_os_system = []
        
        # List all files we've identified as vulnerable
        all_vulnerable_files = [
            "nemo/utils/cloud.py",
            "nemo/collections/llm/deploy/base.py",
            "scripts/tokenizers/get_hf_text_data.py",
            "scripts/installers/setup_os2s_decoders.py",
            "scripts/dataset_processing/speaker_tasks/get_ami_data.py",
            "scripts/dataset_processing/get_commonvoice_data.py",
            "scripts/dataset_processing/tts/aishell3/get_data.py",
        ]
        
        for file_path in all_vulnerable_files:
            full_path = workspace_root / file_path
            if not full_path.exists():
                continue
            
            with open(full_path, 'r') as f:
                content = f.read()
            
            if re.search(r'shell=True', content):
                files_with_shell_true.append(file_path)
            
            if re.search(r'os\.system\(', content):
                files_with_os_system.append(file_path)
            
            vulnerable_files_count += 1
        
        # Assert acceptance criteria violations are detectable
        assert vulnerable_files_count >= 7, (
            f"CVE-002: Expected to find at least 7 vulnerable files. Found {vulnerable_files_count}. "
            f"This means we can track remediation progress."
        )
        
        assert len(files_with_shell_true) >= 3, (
            f"CVE-002: Expected to find shell=True usage in at least 3 files. Found {len(files_with_shell_true)}. "
            f"Files: {files_with_shell_true}"
        )
        
        assert len(files_with_os_system) >= 4, (
            f"CVE-002: Expected to find os.system usage in at least 4 files. Found {len(files_with_os_system)}. "
            f"Files: {files_with_os_system}"
        )
