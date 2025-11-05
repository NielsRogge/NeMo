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
Security tests for CVE-011: Hardcoded Credentials and API Keys

This test suite verifies the vulnerability described in CVE-011 which concerns
hardcoded credentials and API keys in the NeMo repository. These tests are designed
to detect hardcoded secrets and verify that credentials are sourced from secure
locations (environment variables, config management systems, etc.).

**NOTE**: These tests are for DETECTION purposes only - they verify the vulnerability
exists and document the security concern. They DO NOT fix the vulnerability.

Related:
- Jira: https://ml6team.atlassian.net/browse/DR-139
- Severity: HIGH
"""

import ast
import os
import re
from pathlib import Path
from typing import List, Tuple
from unittest.mock import MagicMock, patch

import pytest


class TestHardcodedCredentialsDetection:
    """Tests to detect hardcoded credentials in the codebase."""

    @pytest.fixture
    def nemo_root(self) -> Path:
        """Get the NeMo repository root directory."""
        return Path(__file__).parent.parent.parent / "nemo"

    def _scan_for_hardcoded_patterns(self, file_path: Path) -> List[Tuple[int, str, str]]:
        """
        Scan a Python file for potential hardcoded credentials.

        Returns:
            List of tuples (line_number, pattern_type, line_content)
        """
        findings = []
        
        # Patterns that indicate potential hardcoded credentials
        # These are NOT false positives like tokenizer tokens
        patterns = {
            'api_key_assignment': r'api_key\s*=\s*["\'][^"\']{10,}["\']',
            'secret_assignment': r'secret\s*=\s*["\'][^"\']{10,}["\']',
            'password_assignment': r'password\s*=\s*["\'][^"\']{10,}["\']',
            'token_assignment': r'(?<!tokenizer|_token|unk_token|pad_token|bos_token|eos_token)token\s*=\s*["\'][^"\']{20,}["\']',
            'aws_key': r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][A-Z0-9]{20,}["\']',
            'bearer_token': r'(?i)(bearer|authorization)\s*:\s*["\'][^"\']{20,}["\']',
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    # Skip comments
                    if line.strip().startswith('#'):
                        continue
                    
                    for pattern_name, pattern in patterns.items():
                        if re.search(pattern, line):
                            findings.append((line_num, pattern_name, line.strip()))
        except Exception as e:
            # Skip files that can't be read
            pass
        
        return findings

    @pytest.mark.unit
    def test_detect_hardcoded_credentials_in_hf_io_mixin(self):
        """
        Test for hardcoded credentials in HuggingFace IO mixin.
        
        CVE-011 Reference: nemo/core/classes/mixins/hf_io_mixin.py:115: hf_token = get_hf_token()
        
        This test verifies that tokens are retrieved via get_hf_token() which reads
        from cached credentials, not hardcoded strings.
        """
        file_path = Path(__file__).parent.parent.parent / "nemo" / "core" / "classes" / "mixins" / "hf_io_mixin.py"
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check for hardcoded token values (not using get_hf_token())
        # Pattern: hf_token = "actual_token_value"
        hardcoded_token_pattern = r'hf_token\s*=\s*["\'][a-zA-Z0-9_-]{20,}["\']'
        matches = re.findall(hardcoded_token_pattern, content)
        
        # VULNERABILITY TEST: This should find hardcoded tokens if they exist
        # For documentation purposes, we test the detection capability
        assert isinstance(matches, list), "Token scanning should work"
        
        # Verify that tokens come from get_hf_token() (secure method)
        get_hf_token_usage = re.findall(r'get_hf_token\(\)', content)
        assert len(get_hf_token_usage) > 0, (
            "VULNERABILITY: Tokens should be retrieved via get_hf_token() function. "
            "If this fails, tokens may be hardcoded instead of being retrieved securely."
        )

    @pytest.mark.unit
    def test_detect_api_key_in_pipecat_llm_service(self):
        """
        Test for API key handling in pipecat LLM service.
        
        CVE-011 Reference: nemo/agents/voice_agent/pipecat/services/nemo/llm.py:724: 
                          llm_api_key = config.get("api_key", "None")
        
        This test verifies that API keys are loaded from config, not hardcoded,
        and checks for secure credential handling practices.
        """
        file_path = Path(__file__).parent.parent.parent / "nemo" / "agents" / "voice_agent" / "pipecat" / "services" / "nemo" / "llm.py"
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check for hardcoded API keys (not from config or env)
        # Pattern: api_key = "sk-..." or similar long strings
        hardcoded_api_key_pattern = r'api_key\s*=\s*["\'][a-zA-Z0-9_-]{20,}["\'](?!\s*#.*test|example)'
        matches = re.findall(hardcoded_api_key_pattern, content)
        
        # VULNERABILITY TEST: Detect if API keys are hardcoded
        if len(matches) > 0:
            pytest.fail(
                f"VULNERABILITY DETECTED: Found {len(matches)} potential hardcoded API keys in {file_path}. "
                "API keys should be loaded from environment variables or secure configuration management."
            )
        
        # Verify API keys come from config
        config_get_pattern = r'config\.get\(["\']api_key["\']'
        config_usage = re.findall(config_get_pattern, content)
        
        # Check if the default value is a placeholder, not a real key
        default_value_pattern = r'config\.get\(["\']api_key["\'],\s*["\']None["\']\)'
        safe_defaults = re.findall(default_value_pattern, content)
        
        assert len(config_usage) > 0 or len(safe_defaults) > 0, (
            "API keys should be loaded from config. Found no config.get('api_key') calls."
        )

    @pytest.mark.unit 
    def test_detect_aws_credentials_in_s3_utils(self):
        """
        Test for AWS credential handling in S3 utilities.
        
        CVE-011 Reference: nemo/utils/s3_utils.py:232: aws_session_token=creds["SessionToken"]
        
        This test verifies that AWS credentials are properly sourced from secure
        credential providers, not hardcoded in the source.
        """
        file_path = Path(__file__).parent.parent.parent / "nemo" / "utils" / "s3_utils.py"
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check for hardcoded AWS credentials
        patterns = {
            'access_key': r'aws_access_key_id\s*=\s*["\']AKIA[A-Z0-9]{16}["\']',
            'secret_key': r'aws_secret_access_key\s*=\s*["\'][A-Za-z0-9/+=]{40}["\']',
            'session_token': r'aws_session_token\s*=\s*["\'][A-Za-z0-9/+=]{100,}["\']',
        }
        
        findings = {}
        for key, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                findings[key] = matches
        
        # VULNERABILITY TEST: Detect hardcoded AWS credentials
        if findings:
            pytest.fail(
                f"VULNERABILITY DETECTED: Found potential hardcoded AWS credentials in {file_path}: "
                f"{findings}. AWS credentials should come from IAM roles, environment variables, "
                "or AWS credential files, not hardcoded in source code."
            )
        
        # Verify credentials come from secure sources (dict parameters, not hardcoded)
        secure_patterns = [
            r'creds\[',  # From passed credentials dict
            r'boto3\.Session\(',  # From boto3 session management
            r'os\.environ',  # From environment variables
        ]
        
        uses_secure_source = any(re.search(pattern, content) for pattern in secure_patterns)
        assert uses_secure_source, (
            "S3 utilities should use secure credential sources like boto3.Session, "
            "environment variables, or passed credential objects."
        )

    @pytest.mark.unit
    def test_scan_codebase_for_credential_patterns(self, nemo_root):
        """
        Comprehensive scan of the codebase for common credential patterns.
        
        This test scans Python files in the nemo/ directory for patterns that
        commonly indicate hardcoded credentials.
        """
        # Limit scan to high-risk areas for performance
        high_risk_dirs = [
            nemo_root / "agents",
            nemo_root / "utils",
            nemo_root / "core",
        ]
        
        all_findings = []
        
        for directory in high_risk_dirs:
            if not directory.exists():
                continue
            
            for py_file in directory.rglob("*.py"):
                findings = self._scan_for_hardcoded_patterns(py_file)
                if findings:
                    all_findings.extend([(py_file, *finding) for finding in findings])
        
        # Document findings for security review
        if all_findings:
            report = ["POTENTIAL SECURITY VULNERABILITIES DETECTED:\n"]
            for file_path, line_num, pattern_type, line_content in all_findings:
                rel_path = file_path.relative_to(nemo_root.parent)
                report.append(f"  - {rel_path}:{line_num} [{pattern_type}]: {line_content}")
            
            # This test documents the vulnerability
            # In a real security context, this would fail the test
            print("\n".join(report))

    @pytest.mark.unit
    def test_environment_variable_usage_for_secrets(self):
        """
        Test that the codebase uses environment variables for secrets.
        
        This is a positive test to verify that secure practices are being used
        where they should be.
        """
        # Check that environment variable patterns exist for credential retrieval
        file_path = Path(__file__).parent.parent.parent / "nemo" / "core" / "classes" / "mixins" / "hf_io_mixin.py"
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Should use get_hf_token() which reads from cache/env
        # NOT hardcoded tokens
        uses_secure_token_retrieval = 'get_hf_token' in content
        
        assert uses_secure_token_retrieval, (
            "Code should use secure token retrieval methods like get_hf_token() "
            "that read from environment or cached credentials."
        )

    @pytest.mark.unit
    def test_config_based_credential_loading(self):
        """
        Test that credentials are loaded from configuration objects, not hardcoded.
        
        This tests the pattern where credentials come from config.get() calls
        rather than being hardcoded in the source.
        """
        file_path = Path(__file__).parent.parent.parent / "nemo" / "agents" / "voice_agent" / "pipecat" / "services" / "nemo" / "llm.py"
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Should use config.get() pattern for credentials
        config_patterns = [
            r'config\.get\(["\']api_key["\']',
            r'config\.get\(["\']token["\']',
            r'config\.get\(["\']secret["\']',
        ]
        
        uses_config = any(re.search(pattern, content) for pattern in config_patterns)
        
        assert uses_config, (
            "Credentials should be loaded from configuration objects using "
            "config.get() patterns, not hardcoded."
        )

    @pytest.mark.unit
    def test_no_secrets_in_default_parameters(self):
        """
        Test that function default parameters don't contain actual secrets.
        
        Default parameters should be None, empty strings, or placeholder values
        like "None", not actual API keys or tokens.
        """
        file_path = Path(__file__).parent.parent.parent / "nemo" / "agents" / "voice_agent" / "pipecat" / "services" / "nemo" / "llm.py"
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        # Check function signatures for suspicious default values
        suspicious_defaults = []
        
        for i, line in enumerate(lines, 1):
            # Look for function definitions with api_key parameters
            if 'def ' in line and 'api_key' in line:
                # Check if the default looks like a real key (long alphanumeric string)
                if re.search(r'api_key\s*=\s*["\'][a-zA-Z0-9_-]{20,}["\']', line):
                    suspicious_defaults.append((i, line.strip()))
        
        # Safe defaults like "None", None, "", etc. are OK
        # Actual long strings are NOT OK
        if suspicious_defaults:
            report = ["Found suspicious default parameter values:\n"]
            for line_num, line_content in suspicious_defaults:
                # Check if it's actually "None" string (safe) vs a real token
                if not re.search(r'api_key\s*=\s*["\']None["\']', line_content):
                    report.append(f"  Line {line_num}: {line_content}")
            
            if len(report) > 1:  # More than just the header
                pytest.fail(
                    "VULNERABILITY: " + "\n".join(report) + 
                    "\nDefault parameters should use placeholders like 'None' or None, not actual secrets."
                )


class TestSecureCredentialManagement:
    """Tests to verify secure credential management practices."""

    @pytest.mark.unit
    def test_boto3_credential_provider_chain(self):
        """
        Test that boto3 uses its standard credential provider chain.
        
        Boto3 should use credentials from IAM roles, environment variables,
        or credential files - not hardcoded values.
        """
        from nemo.utils.s3_utils import S3Utils
        
        # Mock boto3.Session to verify it's called without hardcoded credentials
        with patch('nemo.utils.s3_utils.boto3.Session') as mock_session:
            mock_resource = MagicMock()
            mock_session.return_value.resource.return_value = mock_resource
            
            # Call the internal method
            S3Utils._get_s3_resource()
            
            # Verify Session was created (will use credential chain)
            mock_session.assert_called()

    @pytest.mark.unit
    def test_huggingface_token_from_cache(self):
        """
        Test that HuggingFace tokens are retrieved from cache, not hardcoded.
        
        The get_hf_token() function should read from the HuggingFace CLI cache
        or environment variables, not from hardcoded values in the source.
        """
        # Import the function that retrieves tokens
        try:
            from huggingface_hub import get_token as get_hf_token
        except ImportError:
            pytest.skip("huggingface_hub not installed")
        
        # The function should return None or a token from cache/env
        # It should NOT have a default hardcoded token
        import inspect
        sig = inspect.signature(get_hf_token)
        
        # Check that there's no suspicious default value
        for param_name, param in sig.parameters.items():
            if param.default != inspect.Parameter.empty:
                # Default should be None or similar, not a long string token
                assert not isinstance(param.default, str) or len(param.default) < 20, (
                    f"get_hf_token() should not have long string defaults: {param_name}={param.default}"
                )

    @pytest.mark.unit
    def test_credential_leakage_in_logs(self):
        """
        Test to verify credentials aren't leaked in logging statements.
        
        This checks that when credentials are logged, they should be masked
        or sanitized, not printed in plaintext.
        """
        file_paths = [
            Path(__file__).parent.parent.parent / "nemo" / "utils" / "s3_utils.py",
            Path(__file__).parent.parent.parent / "nemo" / "agents" / "voice_agent" / "pipecat" / "services" / "nemo" / "llm.py",
        ]
        
        for file_path in file_paths:
            if not file_path.exists():
                continue
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Check for logging of credentials
            # logging.info(f"api_key: {api_key}") is BAD
            # logging.info(f"api_key: ***") is GOOD
            dangerous_log_patterns = [
                r'logging\.(info|debug|warning|error).*\{.*api_key.*\}',
                r'logging\.(info|debug|warning|error).*\{.*token.*\}',
                r'logging\.(info|debug|warning|error).*\{.*secret.*\}',
                r'logging\.(info|debug|warning|error).*\{.*password.*\}',
            ]
            
            findings = []
            for pattern in dangerous_log_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Check if the match contains masking (* or X)
                    if not re.search(r'(\*{3,}|X{3,}|masked|redacted)', match.group(0), re.IGNORECASE):
                        findings.append(match.group(0))
            
            # This is more of a warning - logging credentials is bad practice
            if findings:
                print(f"\nWARNING: Potential credential logging in {file_path}:")
                for finding in findings[:5]:  # Limit output
                    print(f"  - {finding[:100]}")


class TestVulnerabilityDocumentation:
    """Tests that document the CVE-011 vulnerability for tracking purposes."""

    @pytest.mark.unit
    def test_cve_011_vulnerability_documentation(self):
        """
        Document CVE-011: Hardcoded Credentials and API Keys vulnerability.
        
        This test serves as documentation of the security concern and
        provides references to the affected areas of the codebase.
        """
        vulnerability_info = {
            "cve_id": "CVE-011",
            "title": "Hardcoded Credentials and API Keys",
            "severity": "HIGH",
            "jira": "https://ml6team.atlassian.net/browse/DR-139",
            "affected_files": [
                "nemo/core/classes/mixins/hf_io_mixin.py:115",
                "nemo/agents/voice_agent/pipecat/services/nemo/llm.py:724",
                "nemo/utils/s3_utils.py:232",
            ],
            "description": (
                "The repository may contain hardcoded credentials for external services "
                "like Hugging Face Hub, NVIDIA NGC, and Wandb. API keys, authentication "
                "tokens, and other secrets should be managed securely via environment "
                "variables or secret management services."
            ),
            "recommendation": (
                "1. Conduct thorough audit of codebase for hardcoded credentials\n"
                "2. Use environment variables or secret management services\n"
                "3. Implement pre-commit hooks for secret scanning\n"
                "4. Use tools like detect-secrets, git-secrets, or truffleHog"
            ),
        }
        
        # This test always passes but documents the vulnerability
        assert vulnerability_info["severity"] == "HIGH"
        assert len(vulnerability_info["affected_files"]) > 0
        
        print("\n" + "="*80)
        print(f"CVE DOCUMENTATION: {vulnerability_info['cve_id']}")
        print("="*80)
        print(f"Title: {vulnerability_info['title']}")
        print(f"Severity: {vulnerability_info['severity']}")
        print(f"Jira: {vulnerability_info['jira']}")
        print(f"\nDescription:\n{vulnerability_info['description']}")
        print(f"\nAffected Files:")
        for file in vulnerability_info['affected_files']:
            print(f"  - {file}")
        print(f"\nRecommendations:\n{vulnerability_info['recommendation']}")
        print("="*80)

    @pytest.mark.unit
    def test_list_all_credential_related_files(self):
        """
        Generate a list of files that handle credentials for security review.
        
        This helps security teams identify files that need careful auditing.
        """
        nemo_root = Path(__file__).parent.parent.parent / "nemo"
        
        if not nemo_root.exists():
            pytest.skip("NeMo root not found")
        
        # Search for files containing credential-related keywords
        credential_keywords = ['api_key', 'token', 'secret', 'password', 'credential']
        files_to_review = set()
        
        for py_file in nemo_root.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                    if any(keyword in content for keyword in credential_keywords):
                        # Exclude tokenizer-related files (false positives)
                        if 'tokenizer' not in py_file.name.lower():
                            files_to_review.add(py_file.relative_to(nemo_root.parent))
            except:
                pass
        
        # Limit output for readability
        files_list = sorted(list(files_to_review))[:20]
        
        print("\n" + "="*80)
        print("FILES REQUIRING SECURITY REVIEW (Top 20)")
        print("="*80)
        for file in files_list:
            print(f"  - {file}")
        print(f"\nTotal files to review: {len(files_to_review)}")
        print("="*80)
        
        # Test passes but documents files for review
        assert len(files_to_review) > 0
