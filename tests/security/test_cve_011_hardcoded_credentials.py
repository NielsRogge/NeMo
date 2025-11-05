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
Security Tests for CVE-011: Hardcoded Credentials and API Keys

These tests are designed to DETECT the vulnerability, not fix it.
They verify that hardcoded credentials exist in the codebase.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest


class TestHardcodedCredentials:
    """
    Test suite for CVE-011: Hardcoded Credentials and API Keys vulnerability.
    
    This test suite scans the NeMo codebase for potential hardcoded credentials,
    API keys, tokens, and other sensitive information that should not be stored
    directly in the source code.
    """

    # Patterns that indicate potential hardcoded credentials
    CREDENTIAL_PATTERNS = [
        # AWS credentials
        (r'aws_access_key_id\s*=\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key ID'),
        (r'aws_secret_access_key\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']', 'AWS Secret Access Key'),
        (r'AWS_ACCESS_KEY_ID\s*=\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key ID (env var style)'),
        (r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']', 'AWS Secret Access Key (env var style)'),
        
        # API Keys (generic)
        (r'api_key\s*=\s*["\']([A-Za-z0-9]{32,})["\']', 'Generic API Key'),
        (r'apikey\s*=\s*["\']([A-Za-z0-9]{32,})["\']', 'Generic API Key (no underscore)'),
        
        # HuggingFace tokens
        (r'hf_token\s*=\s*["\']([A-Za-z0-9_]{32,})["\']', 'HuggingFace Token'),
        (r'HUGGINGFACE_TOKEN\s*=\s*["\']([A-Za-z0-9_]{32,})["\']', 'HuggingFace Token (env var style)'),
        (r'HF_TOKEN\s*=\s*["\']([A-Za-z0-9_]{32,})["\']', 'HuggingFace Token (short env var)'),
        
        # Wandb API keys
        (r'wandb_api_key\s*=\s*["\']([A-Za-z0-9]{40})["\']', 'Wandb API Key'),
        (r'WANDB_API_KEY\s*=\s*["\']([A-Za-z0-9]{40})["\']', 'Wandb API Key (env var style)'),
        
        # NGC API keys
        (r'ngc_api_key\s*=\s*["\']([A-Za-z0-9\-]{36,})["\']', 'NGC API Key'),
        (r'NGC_API_KEY\s*=\s*["\']([A-Za-z0-9\-]{36,})["\']', 'NGC API Key (env var style)'),
        
        # Passwords
        (r'password\s*=\s*["\']([^"\'\s]{8,})["\']', 'Password'),
        (r'PASSWORD\s*=\s*["\']([^"\'\s]{8,})["\']', 'Password (env var style)'),
        
        # Bearer tokens
        (r'bearer\s+["\']([A-Za-z0-9\-._~+/]+=*)["\']', 'Bearer Token'),
        (r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)', 'Bearer Token (header style)'),
        
        # Generic tokens
        (r'token\s*=\s*["\']([A-Za-z0-9\-._~+/]{32,})["\']', 'Generic Token'),
        (r'TOKEN\s*=\s*["\']([A-Za-z0-9\-._~+/]{32,})["\']', 'Generic Token (env var style)'),
        
        # Secret keys
        (r'secret_key\s*=\s*["\']([A-Za-z0-9\-._~+/]{32,})["\']', 'Secret Key'),
        (r'SECRET_KEY\s*=\s*["\']([A-Za-z0-9\-._~+/]{32,})["\']', 'Secret Key (env var style)'),
    ]
    
    # Files to exclude from scanning (test files, documentation, etc.)
    EXCLUDED_PATTERNS = [
        'test_*',
        '*_test.py',
        '*.md',
        '*.rst',
        '*.txt',
        '*.yaml',
        '*.json',
        '*.sh',
        'conftest.py',
    ]
    
    # Specific files mentioned in CVE-011
    CVE_MENTIONED_FILES = [
        'nemo/core/classes/mixins/hf_io_mixin.py',
        'nemo/agents/voice_agent/pipecat/services/nemo/llm.py',
        'nemo/utils/s3_utils.py',
    ]

    @pytest.fixture
    def nemo_root_path(self) -> Path:
        """Get the root path of the NeMo repository."""
        # Get the path to the tests directory, then go up one level
        tests_dir = Path(__file__).parent.parent
        nemo_root = tests_dir.parent
        return nemo_root

    def _should_scan_file(self, file_path: Path) -> bool:
        """
        Determine if a file should be scanned for credentials.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if the file should be scanned, False otherwise
        """
        # Only scan Python files
        if file_path.suffix != '.py':
            return False
        
        # Skip excluded patterns
        for pattern in self.EXCLUDED_PATTERNS:
            if file_path.match(pattern):
                return False
        
        return True

    def _scan_file_for_credentials(self, file_path: Path) -> List[Tuple[int, str, str, str]]:
        """
        Scan a single file for hardcoded credentials.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of tuples containing (line_number, pattern_name, matched_value, line_content)
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, start=1):
                # Skip comments
                stripped_line = line.strip()
                if stripped_line.startswith('#'):
                    continue
                
                # Check against all credential patterns
                for pattern, pattern_name in self.CREDENTIAL_PATTERNS:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        # Extract the matched credential value
                        matched_value = match.group(1) if match.groups() else match.group(0)
                        findings.append((line_num, pattern_name, matched_value, line.strip()))
        
        except Exception as e:
            # If we can't read the file, skip it
            pass
        
        return findings

    def test_scan_specific_cve_mentioned_files(self, nemo_root_path):
        """
        Test for hardcoded credentials in files specifically mentioned in CVE-011.
        
        This test scans the three files explicitly mentioned in the CVE report:
        - nemo/core/classes/mixins/hf_io_mixin.py (line 115: hf_token = get_hf_token())
        - nemo/agents/voice_agent/pipecat/services/nemo/llm.py (line 724: llm_api_key = config.get("api_key", "None"))
        - nemo/utils/s3_utils.py (line 232: aws_session_token=creds["SessionToken"])
        
        Expected: These files should use secure credential retrieval methods.
        """
        findings = {}
        
        for relative_path in self.CVE_MENTIONED_FILES:
            file_path = nemo_root_path / relative_path
            
            if not file_path.exists():
                continue
            
            file_findings = self._scan_file_for_credentials(file_path)
            if file_findings:
                findings[relative_path] = file_findings
        
        # Report findings
        if findings:
            report = "\n\nHardcoded credentials detected in CVE-mentioned files:\n"
            for file_path, file_findings in findings.items():
                report += f"\n{file_path}:\n"
                for line_num, pattern_name, matched_value, line_content in file_findings:
                    report += f"  Line {line_num}: {pattern_name}\n"
                    report += f"    Matched: {matched_value[:20]}...\n"
                    report += f"    Context: {line_content}\n"
            
            pytest.fail(f"Found {sum(len(v) for v in findings.values())} potential hardcoded credentials{report}")

    def test_check_hf_token_usage(self, nemo_root_path):
        """
        Test that HuggingFace tokens are retrieved securely.
        
        This test specifically checks the usage pattern in hf_io_mixin.py where
        tokens should be retrieved using get_hf_token() function instead of
        being hardcoded.
        
        Expected: Tokens should be retrieved via get_hf_token() or from environment variables.
        """
        hf_mixin_file = nemo_root_path / 'nemo/core/classes/mixins/hf_io_mixin.py'
        
        if not hf_mixin_file.exists():
            pytest.skip(f"File not found: {hf_mixin_file}")
        
        with open(hf_mixin_file, 'r') as f:
            content = f.read()
        
        # Check for hardcoded token patterns
        hardcoded_token_patterns = [
            r'hf_token\s*=\s*["\'][A-Za-z0-9_]{32,}["\']',
            r'token\s*=\s*["\']hf_[A-Za-z0-9_]{32,}["\']',
        ]
        
        findings = []
        for pattern in hardcoded_token_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                findings.append((line_num, match.group(0)))
        
        if findings:
            report = "\n\nHardcoded HuggingFace tokens detected:\n"
            for line_num, matched_text in findings:
                report += f"  Line {line_num}: {matched_text}\n"
            
            pytest.fail(f"Found {len(findings)} hardcoded HuggingFace tokens{report}")

    def test_check_api_key_config_retrieval(self, nemo_root_path):
        """
        Test that API keys retrieved from config have secure defaults.
        
        This test checks the pattern in llm.py where API keys are retrieved
        from config objects. The default value should not be a real API key.
        
        Expected: Default values for API keys should be None, empty string, or
                 a placeholder like "None" (string), not actual credentials.
        """
        llm_file = nemo_root_path / 'nemo/agents/voice_agent/pipecat/services/nemo/llm.py'
        
        if not llm_file.exists():
            pytest.skip(f"File not found: {llm_file}")
        
        with open(llm_file, 'r') as f:
            lines = f.readlines()
        
        # Pattern: config.get("api_key", "<default_value>")
        # The default value should not look like a real API key
        api_key_pattern = r'config\.get\(["\']api_key["\'],\s*["\']([A-Za-z0-9]{32,})["\']'
        
        findings = []
        for line_num, line in enumerate(lines, start=1):
            match = re.search(api_key_pattern, line)
            if match:
                default_value = match.group(1)
                # Check if the default value looks like a real API key
                # Real API keys are typically long alphanumeric strings
                if len(default_value) >= 32 and default_value not in ['None', 'none', 'null']:
                    findings.append((line_num, default_value, line.strip()))
        
        if findings:
            report = "\n\nPotential hardcoded API keys found as default values:\n"
            for line_num, default_value, line_content in findings:
                report += f"  Line {line_num}: Default value '{default_value}'\n"
                report += f"    Context: {line_content}\n"
            
            pytest.fail(f"Found {len(findings)} potential hardcoded API keys as defaults{report}")

    def test_check_aws_credentials_handling(self, nemo_root_path):
        """
        Test that AWS credentials are handled securely.
        
        This test checks s3_utils.py to ensure AWS credentials are not hardcoded
        and are properly retrieved from secure sources (IAM roles, environment
        variables, or credential files).
        
        Expected: AWS credentials should be retrieved from boto3 session or passed
                 as parameters, not hardcoded in the source.
        """
        s3_utils_file = nemo_root_path / 'nemo/utils/s3_utils.py'
        
        if not s3_utils_file.exists():
            pytest.skip(f"File not found: {s3_utils_file}")
        
        with open(s3_utils_file, 'r') as f:
            content = f.read()
        
        # Patterns for hardcoded AWS credentials
        aws_credential_patterns = [
            (r'aws_access_key_id\s*=\s*["\']AKIA[A-Z0-9]{16}["\']', 'AWS Access Key ID'),
            (r'aws_secret_access_key\s*=\s*["\'][A-Za-z0-9/+=]{40}["\']', 'AWS Secret Access Key'),
            (r'aws_session_token\s*=\s*["\'][A-Za-z0-9/+=]{100,}["\']', 'AWS Session Token'),
        ]
        
        findings = []
        for pattern, credential_type in aws_credential_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                findings.append((line_num, credential_type, match.group(0)))
        
        if findings:
            report = "\n\nHardcoded AWS credentials detected:\n"
            for line_num, credential_type, matched_text in findings:
                report += f"  Line {line_num}: {credential_type}\n"
                report += f"    Pattern: {matched_text[:50]}...\n"
            
            pytest.fail(f"Found {len(findings)} hardcoded AWS credentials{report}")

    def test_scan_entire_nemo_directory(self, nemo_root_path):
        """
        Comprehensive scan of the entire NeMo codebase for hardcoded credentials.
        
        This test performs a full scan of all Python files in the nemo/ directory
        looking for patterns that match common credential formats.
        
        Expected: No hardcoded credentials should be found in the codebase.
        """
        nemo_dir = nemo_root_path / 'nemo'
        
        if not nemo_dir.exists():
            pytest.skip(f"Directory not found: {nemo_dir}")
        
        all_findings = {}
        
        # Recursively scan all Python files
        for py_file in nemo_dir.rglob('*.py'):
            if not self._should_scan_file(py_file):
                continue
            
            file_findings = self._scan_file_for_credentials(py_file)
            if file_findings:
                relative_path = py_file.relative_to(nemo_root_path)
                all_findings[str(relative_path)] = file_findings
        
        if all_findings:
            total_findings = sum(len(v) for v in all_findings.values())
            report = f"\n\nFound {total_findings} potential hardcoded credentials in {len(all_findings)} files:\n"
            
            # Limit report to first 20 findings for readability
            displayed_count = 0
            max_display = 20
            
            for file_path, file_findings in all_findings.items():
                report += f"\n{file_path}:\n"
                for line_num, pattern_name, matched_value, line_content in file_findings:
                    if displayed_count >= max_display:
                        remaining = total_findings - displayed_count
                        report += f"\n... and {remaining} more findings\n"
                        break
                    
                    report += f"  Line {line_num}: {pattern_name}\n"
                    report += f"    Context: {line_content}\n"
                    displayed_count += 1
                
                if displayed_count >= max_display:
                    break
            
            pytest.fail(f"Found {total_findings} potential hardcoded credentials in {len(all_findings)} files{report}")

    def test_check_environment_variable_usage(self, nemo_root_path):
        """
        Test that credentials are retrieved from environment variables properly.
        
        This test checks that when credentials are read from environment variables,
        no default hardcoded values are provided that could be actual credentials.
        
        Expected: Environment variable retrievals should have safe defaults (None,
                 empty string, or clearly placeholder values).
        """
        nemo_dir = nemo_root_path / 'nemo'
        
        if not nemo_dir.exists():
            pytest.skip(f"Directory not found: {nemo_dir}")
        
        # Pattern: os.environ.get() or os.getenv() with a default value that looks like a credential
        env_patterns = [
            (r'os\.environ\.get\(["\']([A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z_]*)["\'],\s*["\']([A-Za-z0-9]{32,})["\']', 
             'os.environ.get with potential hardcoded default'),
            (r'os\.getenv\(["\']([A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z_]*)["\'],\s*["\']([A-Za-z0-9]{32,})["\']', 
             'os.getenv with potential hardcoded default'),
        ]
        
        findings = []
        
        for py_file in nemo_dir.rglob('*.py'):
            if not self._should_scan_file(py_file):
                continue
            
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                for line_num, line in enumerate(lines, start=1):
                    for pattern, description in env_patterns:
                        match = re.search(pattern, line)
                        if match:
                            env_var_name = match.group(1)
                            default_value = match.group(2)
                            
                            # Check if default value looks like a real credential
                            if len(default_value) >= 32 and default_value.lower() not in ['none', 'null', 'undefined']:
                                relative_path = py_file.relative_to(nemo_root_path)
                                findings.append((str(relative_path), line_num, env_var_name, default_value, line.strip()))
            
            except Exception:
                # Skip files that can't be read
                continue
        
        if findings:
            report = "\n\nFound environment variable retrievals with potential hardcoded defaults:\n"
            for file_path, line_num, env_var, default_value, line_content in findings[:20]:
                report += f"\n{file_path}:{line_num}\n"
                report += f"  Environment Variable: {env_var}\n"
                report += f"  Default Value: {default_value[:30]}...\n"
                report += f"  Context: {line_content}\n"
            
            if len(findings) > 20:
                report += f"\n... and {len(findings) - 20} more findings\n"
            
            pytest.fail(f"Found {len(findings)} environment variables with suspicious defaults{report}")

    def test_check_for_base64_encoded_secrets(self, nemo_root_path):
        """
        Test for Base64-encoded secrets that might be hardcoded.
        
        Some developers try to obfuscate hardcoded credentials by Base64-encoding them.
        This test looks for suspicious Base64 strings that might be encoded credentials.
        
        Expected: No Base64-encoded credentials should be hardcoded.
        """
        nemo_dir = nemo_root_path / 'nemo'
        
        if not nemo_dir.exists():
            pytest.skip(f"Directory not found: {nemo_dir}")
        
        # Pattern for Base64 strings (at least 32 characters)
        # This pattern looks for strings that are likely Base64-encoded values
        base64_pattern = r'["\']([A-Za-z0-9+/]{32,}={0,2})["\']'
        
        # Context patterns that suggest this might be a credential
        credential_context_patterns = [
            r'token',
            r'key',
            r'secret',
            r'password',
            r'credential',
            r'auth',
        ]
        
        findings = []
        
        for py_file in nemo_dir.rglob('*.py'):
            if not self._should_scan_file(py_file):
                continue
            
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                for line_num, line in enumerate(lines, start=1):
                    # Skip comments
                    if line.strip().startswith('#'):
                        continue
                    
                    # Check for Base64 pattern
                    matches = re.finditer(base64_pattern, line)
                    for match in matches:
                        base64_string = match.group(1)
                        
                        # Check if the line contains credential-related keywords
                        line_lower = line.lower()
                        has_credential_context = any(
                            pattern in line_lower for pattern in credential_context_patterns
                        )
                        
                        # Only flag if it has credential context and is sufficiently long
                        if has_credential_context and len(base64_string) >= 40:
                            relative_path = py_file.relative_to(nemo_root_path)
                            findings.append((str(relative_path), line_num, base64_string[:40], line.strip()))
            
            except Exception:
                continue
        
        if findings:
            report = "\n\nFound potential Base64-encoded credentials:\n"
            for file_path, line_num, base64_value, line_content in findings[:20]:
                report += f"\n{file_path}:{line_num}\n"
                report += f"  Potential encoded value: {base64_value}...\n"
                report += f"  Context: {line_content}\n"
            
            if len(findings) > 20:
                report += f"\n... and {len(findings) - 20} more findings\n"
            
            pytest.fail(f"Found {len(findings)} potential Base64-encoded credentials{report}")


class TestConfigurationFileCredentials:
    """
    Test suite for checking YAML/JSON configuration files for hardcoded credentials.
    
    While the main focus is on Python files, configuration files can also contain
    hardcoded credentials.
    """

    def test_scan_yaml_config_files(self, tmp_path):
        """
        Test that YAML configuration files don't contain hardcoded credentials.
        
        This test scans YAML files in the examples directory to ensure no
        credentials are accidentally checked in.
        
        Expected: No hardcoded credentials in configuration files.
        """
        # Get the root path
        tests_dir = Path(__file__).parent.parent
        nemo_root = tests_dir.parent
        examples_dir = nemo_root / 'examples'
        
        if not examples_dir.exists():
            pytest.skip(f"Directory not found: {examples_dir}")
        
        # Patterns to look for in YAML files
        yaml_credential_patterns = [
            r'api_key:\s*["\']?([A-Za-z0-9]{32,})["\']?',
            r'token:\s*["\']?([A-Za-z0-9_\-]{32,})["\']?',
            r'password:\s*["\']?([^"\'\s]{8,})["\']?',
            r'secret:\s*["\']?([A-Za-z0-9]{32,})["\']?',
        ]
        
        findings = []
        
        for yaml_file in examples_dir.rglob('*.yaml'):
            try:
                with open(yaml_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                for line_num, line in enumerate(lines, start=1):
                    # Skip comments
                    if line.strip().startswith('#'):
                        continue
                    
                    for pattern in yaml_credential_patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            matched_value = match.group(1)
                            
                            # Filter out obvious placeholders
                            if matched_value.lower() in ['none', 'null', 'your_api_key_here', 'placeholder']:
                                continue
                            
                            relative_path = yaml_file.relative_to(nemo_root)
                            findings.append((str(relative_path), line_num, matched_value, line.strip()))
            
            except Exception:
                continue
        
        if findings:
            report = "\n\nFound potential hardcoded credentials in YAML files:\n"
            for file_path, line_num, matched_value, line_content in findings[:20]:
                report += f"\n{file_path}:{line_num}\n"
                report += f"  Matched: {matched_value[:30]}...\n"
                report += f"  Context: {line_content}\n"
            
            if len(findings) > 20:
                report += f"\n... and {len(findings) - 20} more findings\n"
            
            pytest.fail(f"Found {len(findings)} potential hardcoded credentials in YAML files{report}")
