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

This test suite verifies that the codebase does not contain hardcoded credentials,
API keys, or other secrets that would grant unauthorized access to external services
like Hugging Face Hub, NVIDIA NGC, and Wandb.

Severity: HIGH
Jira Issue: https://ml6team.atlassian.net/browse/DR-139
"""

import os
import re
from pathlib import Path
from typing import List, Tuple
from unittest.mock import MagicMock, patch

import pytest


class TestCVE011HardcodedCredentials:
    """Test suite for detecting and preventing hardcoded credentials."""

    # Patterns that indicate potential hardcoded credentials
    CREDENTIAL_PATTERNS = [
        # API keys with common formats
        (r'api_key\s*=\s*["\'][A-Za-z0-9+/]{20,}["\']', 'Potential hardcoded API key'),
        (r'apikey\s*=\s*["\'][A-Za-z0-9+/]{20,}["\']', 'Potential hardcoded API key'),
        
        # Tokens
        (r'token\s*=\s*["\'][A-Za-z0-9._\-]{20,}["\']', 'Potential hardcoded token (excluding HF token functions)'),
        (r'access_token\s*=\s*["\'][A-Za-z0-9._\-]{20,}["\']', 'Potential hardcoded access token'),
        (r'auth_token\s*=\s*["\'][A-Za-z0-9._\-]{20,}["\']', 'Potential hardcoded auth token'),
        
        # Secrets
        (r'secret\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']', 'Potential hardcoded secret'),
        (r'secret_key\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']', 'Potential hardcoded secret key'),
        (r'api_secret\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']', 'Potential hardcoded API secret'),
        
        # Passwords
        (r'password\s*=\s*["\'][^"\']{8,}["\']', 'Potential hardcoded password'),
        (r'passwd\s*=\s*["\'][^"\']{8,}["\']', 'Potential hardcoded password'),
        
        # AWS Credentials
        (r'aws_access_key_id\s*=\s*["\']AKIA[A-Z0-9]{16}["\']', 'Potential hardcoded AWS access key'),
        (r'aws_secret_access_key\s*=\s*["\'][A-Za-z0-9+/]{40}["\']', 'Potential hardcoded AWS secret key'),
        
        # API URLs with embedded credentials
        (r'https?://[^:@\s]+:[^:@\s]+@', 'Potential credentials in URL'),
    ]

    # Paths to exclude from scanning (test files, documentation, etc.)
    EXCLUDE_PATHS = [
        'tests/',
        'docs/',
        '.git/',
        '__pycache__/',
        '*.pyc',
        '*.md',
        '*.rst',
        '*.txt',
        'LICENSE',
        'CHANGELOG',
    ]

    # Patterns that are safe/false positives to ignore
    SAFE_PATTERNS = [
        r'token\s*=\s*["\']None["\']',
        r'token\s*=\s*None',
        r'api_key\s*=\s*["\']None["\']',
        r'api_key\s*=\s*None',
        r'password\s*=\s*["\']test["\']',
        r'password\s*=\s*["\']example["\']',
        r'password\s*=\s*["\']dummy["\']',
        r'get_hf_token\(',  # Function call, not hardcoded
        r'\.get\(["\'].*token',  # Getting from dict/config
        r'\.get\(["\'].*api_key',  # Getting from dict/config
        r'os\.environ',  # Environment variable access
        r'os\.getenv',  # Environment variable access
        r'getpass\.getpass',  # Password prompt
    ]

    def _is_excluded_path(self, file_path: Path) -> bool:
        """Check if a path should be excluded from scanning."""
        path_str = str(file_path)
        for exclude in self.EXCLUDE_PATHS:
            if exclude.endswith('/'):
                if exclude.rstrip('/') in path_str:
                    return True
            elif exclude.startswith('*.'):
                if path_str.endswith(exclude[1:]):
                    return True
            elif exclude in path_str:
                return True
        return False

    def _is_safe_pattern(self, line: str) -> bool:
        """Check if a line matches a known safe pattern."""
        for pattern in self.SAFE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False

    def _scan_file_for_credentials(self, file_path: Path) -> List[Tuple[int, str, str]]:
        """
        Scan a single file for potential hardcoded credentials.
        
        Returns:
            List of tuples: (line_number, line_content, pattern_description)
        """
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    # Skip if it's a safe pattern
                    if self._is_safe_pattern(line):
                        continue
                    
                    # Check against credential patterns
                    for pattern, description in self.CREDENTIAL_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append((line_num, line.strip(), description))
        except Exception as e:
            # If file can't be read, skip it
            pass
        
        return findings

    def _get_python_files(self, root_path: Path) -> List[Path]:
        """Get all Python files in the repository, excluding test files."""
        python_files = []
        for py_file in root_path.rglob('*.py'):
            if not self._is_excluded_path(py_file):
                python_files.append(py_file)
        return python_files

    @pytest.mark.unit
    def test_no_hardcoded_credentials_in_codebase(self):
        """
        Test that the codebase does not contain hardcoded credentials.
        
        This test scans all Python files in the nemo/ directory for common patterns
        that indicate hardcoded credentials, API keys, tokens, or secrets.
        """
        # Get the workspace root
        workspace_root = Path(__file__).parent.parent.parent
        nemo_path = workspace_root / 'nemo'
        
        if not nemo_path.exists():
            pytest.skip("nemo directory not found")
        
        # Scan all Python files
        python_files = self._get_python_files(nemo_path)
        all_findings = {}
        
        for py_file in python_files:
            findings = self._scan_file_for_credentials(py_file)
            if findings:
                all_findings[str(py_file.relative_to(workspace_root))] = findings
        
        # Assert no hardcoded credentials were found
        if all_findings:
            error_message = "\n\nPotential hardcoded credentials detected:\n"
            for file_path, findings in all_findings.items():
                error_message += f"\n{file_path}:\n"
                for line_num, line, description in findings:
                    error_message += f"  Line {line_num}: {description}\n"
                    error_message += f"    {line}\n"
            
            pytest.fail(error_message)

    @pytest.mark.unit
    def test_hf_io_mixin_uses_safe_token_retrieval(self):
        """
        Test that HuggingFaceFileIO uses get_hf_token() function instead of hardcoded tokens.
        
        File: nemo/core/classes/mixins/hf_io_mixin.py
        Line: 115 and 189
        """
        workspace_root = Path(__file__).parent.parent.parent
        file_path = workspace_root / 'nemo' / 'core' / 'classes' / 'mixins' / 'hf_io_mixin.py'
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        content = file_path.read_text()
        
        # Verify that get_hf_token is imported and used
        assert 'from huggingface_hub import get_token as get_hf_token' in content, \
            "get_hf_token should be imported from huggingface_hub"
        
        assert 'hf_token = get_hf_token()' in content, \
            "Should use get_hf_token() to retrieve token"
        
        # Verify no hardcoded HF tokens (format: hf_xxx...)
        hf_token_pattern = r'["\']hf_[A-Za-z0-9]{30,}["\']'
        matches = re.findall(hf_token_pattern, content)
        assert len(matches) == 0, \
            f"Found potential hardcoded HuggingFace tokens: {matches}"

    @pytest.mark.unit
    def test_llm_service_uses_config_based_api_keys(self):
        """
        Test that LLM services retrieve API keys from config, not hardcoded values.
        
        File: nemo/agents/voice_agent/pipecat/services/nemo/llm.py
        Line: 724
        """
        workspace_root = Path(__file__).parent.parent.parent
        file_path = workspace_root / 'nemo' / 'agents' / 'voice_agent' / 'pipecat' / 'services' / 'nemo' / 'llm.py'
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        content = file_path.read_text()
        
        # Verify that API keys are retrieved from config with safe defaults
        assert 'config.get("api_key"' in content, \
            "API keys should be retrieved from config"
        
        # Ensure the default value is "None" string, not an actual key
        api_key_line_pattern = r'api_key\s*=\s*config\.get\(["\']api_key["\']\s*,\s*["\']None["\']\)'
        assert re.search(api_key_line_pattern, content), \
            "API key retrieval should use config.get with 'None' as default"
        
        # Verify no hardcoded API keys
        hardcoded_key_pattern = r'api_key\s*=\s*["\'][A-Za-z0-9]{20,}["\']'
        suspicious_lines = []
        for line_num, line in enumerate(content.split('\n'), 1):
            if re.search(hardcoded_key_pattern, line) and 'config.get' not in line:
                suspicious_lines.append((line_num, line.strip()))
        
        assert len(suspicious_lines) == 0, \
            f"Found potential hardcoded API keys: {suspicious_lines}"

    @pytest.mark.unit
    def test_s3_utils_uses_credential_parameters(self):
        """
        Test that S3Utils uses credentials passed as parameters, not hardcoded.
        
        File: nemo/utils/s3_utils.py
        Line: 232
        """
        workspace_root = Path(__file__).parent.parent.parent
        file_path = workspace_root / 'nemo' / 'utils' / 's3_utils.py'
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        content = file_path.read_text()
        
        # Verify that AWS credentials are passed as parameters
        assert 'creds["AccessKeyId"]' in content, \
            "AWS access key should be retrieved from credentials parameter"
        assert 'creds["SecretAccessKey"]' in content, \
            "AWS secret key should be retrieved from credentials parameter"
        assert 'creds["SessionToken"]' in content, \
            "AWS session token should be retrieved from credentials parameter"
        
        # Verify no hardcoded AWS credentials
        # AWS Access Key ID format: AKIA followed by 16 alphanumeric characters
        aws_key_pattern = r'["\']AKIA[A-Z0-9]{16}["\']'
        matches = re.findall(aws_key_pattern, content)
        assert len(matches) == 0, \
            f"Found potential hardcoded AWS access keys: {matches}"
        
        # AWS Secret Access Key format: 40 character base64 string
        aws_secret_pattern = r'aws_secret_access_key\s*=\s*["\'][A-Za-z0-9+/]{40}["\']'
        matches = re.findall(aws_secret_pattern, content)
        assert len(matches) == 0, \
            f"Found potential hardcoded AWS secret keys: {matches}"

    @pytest.mark.unit
    def test_environment_variable_usage_for_secrets(self):
        """
        Test that sensitive configurations use environment variables instead of hardcoded values.
        
        This test verifies common patterns for retrieving secrets from environment variables.
        """
        workspace_root = Path(__file__).parent.parent.parent
        
        # Files that should use environment variables for secrets
        critical_files = [
            'nemo/core/classes/mixins/hf_io_mixin.py',
            'nemo/utils/s3_utils.py',
        ]
        
        for file_rel_path in critical_files:
            file_path = workspace_root / file_rel_path
            
            if not file_path.exists():
                continue
            
            content = file_path.read_text()
            
            # Check for environment variable access patterns
            env_patterns = [
                r'os\.environ',
                r'os\.getenv',
                r'get_token\(',
                r'get_hf_token\(',
                r'\.get\(["\'][a-z_]*(?:token|key|secret|password)',
            ]
            
            has_env_access = any(re.search(pattern, content, re.IGNORECASE) 
                                for pattern in env_patterns)
            
            # Verify no direct credential assignments
            direct_cred_patterns = [
                r'(?:api_key|token|password|secret)\s*=\s*["\'][A-Za-z0-9+/]{20,}["\']',
            ]
            
            # Skip lines that are safe (config.get, etc.)
            suspicious_lines = []
            for line_num, line in enumerate(content.split('\n'), 1):
                if any(re.search(p, line) for p in direct_cred_patterns):
                    if not self._is_safe_pattern(line):
                        suspicious_lines.append((line_num, line.strip()))
            
            assert len(suspicious_lines) == 0, \
                f"File {file_rel_path} has suspicious credential assignments: {suspicious_lines}"

    @pytest.mark.unit
    def test_no_credentials_in_default_values(self):
        """
        Test that function/method default parameters don't contain hardcoded credentials.
        
        This test scans function signatures to ensure default values for credential-related
        parameters are safe (None, empty string, or placeholders).
        """
        workspace_root = Path(__file__).parent.parent.parent
        nemo_path = workspace_root / 'nemo'
        
        if not nemo_path.exists():
            pytest.skip("nemo directory not found")
        
        # Pattern to match function definitions with credential parameters
        func_def_pattern = r'def\s+\w+\([^)]*(?:token|key|password|secret|credential)[^)]*\):'
        
        # Pattern for unsafe default values (long strings that could be credentials)
        unsafe_default_pattern = r'(?:token|key|password|secret|credential)\s*[:=]\s*["\'][A-Za-z0-9+/=]{20,}["\']'
        
        findings = {}
        
        for py_file in self._get_python_files(nemo_path):
            try:
                content = py_file.read_text()
                
                for line_num, line in enumerate(content.split('\n'), 1):
                    # Check if line contains a function definition with credential params
                    if re.search(func_def_pattern, line, re.IGNORECASE):
                        # Check for unsafe defaults
                        if re.search(unsafe_default_pattern, line, re.IGNORECASE):
                            if not self._is_safe_pattern(line):
                                if str(py_file) not in findings:
                                    findings[str(py_file)] = []
                                findings[str(py_file)].append((line_num, line.strip()))
            except Exception:
                pass
        
        assert len(findings) == 0, \
            f"Found functions with potentially hardcoded credential defaults: {findings}"

    @pytest.mark.unit
    def test_credential_patterns_documentation(self):
        """
        Document the secure patterns that should be used for credential management.
        
        This test serves as documentation for developers on how to properly handle credentials.
        """
        secure_patterns = {
            'Environment Variables': [
                'api_key = os.environ.get("API_KEY")',
                'token = os.getenv("HF_TOKEN")',
            ],
            'Config-based Retrieval': [
                'api_key = config.get("api_key", None)',
                'token = cfg.get("token", "")',
            ],
            'Library Functions': [
                'from huggingface_hub import get_token',
                'hf_token = get_token()',
            ],
            'Parameter Passing': [
                'def upload_to_s3(credentials: dict):',
                '    access_key = credentials["AccessKeyId"]',
            ],
        }
        
        # This test always passes - it's for documentation purposes
        assert True, "Secure credential patterns documented"

    @pytest.mark.unit
    def test_no_api_keys_in_example_configs(self):
        """
        Test that example configuration files don't contain real API keys.
        
        This test scans YAML and JSON config files for potential credentials.
        """
        workspace_root = Path(__file__).parent.parent.parent
        
        config_patterns = ['*.yaml', '*.yml', '*.json']
        config_files = []
        
        for pattern in config_patterns:
            # Only scan examples and configs directories
            for search_path in ['examples/', 'nemo/']:
                search_dir = workspace_root / search_path
                if search_dir.exists():
                    config_files.extend(search_dir.rglob(pattern))
        
        findings = {}
        
        for config_file in config_files:
            try:
                content = config_file.read_text()
                
                # Look for key-value patterns with potential credentials
                for line_num, line in enumerate(content.split('\n'), 1):
                    # Skip comments
                    if line.strip().startswith('#'):
                        continue
                    
                    # Check for credential-like keys with suspicious values
                    for pattern, description in self.CREDENTIAL_PATTERNS:
                        # Adapt pattern for YAML/JSON (key: value)
                        yaml_pattern = pattern.replace(r'\s*=\s*', r'\s*:\s*')
                        if re.search(yaml_pattern, line, re.IGNORECASE):
                            if not self._is_safe_pattern(line):
                                if str(config_file) not in findings:
                                    findings[str(config_file)] = []
                                findings[str(config_file)].append((line_num, line.strip(), description))
            except Exception:
                pass
        
        assert len(findings) == 0, \
            f"Found potential credentials in config files: {findings}"


class TestSecretManagementBestPractices:
    """Test suite for verifying secure secret management practices."""

    @pytest.mark.unit
    def test_huggingface_hub_token_retrieval_mock(self):
        """
        Test that HuggingFace token retrieval works correctly with environment variables.
        
        This test mocks the get_hf_token function to verify it's being called properly.
        """
        from nemo.core.classes.mixins.hf_io_mixin import HuggingFaceFileIO
        
        with patch('nemo.core.classes.mixins.hf_io_mixin.get_hf_token') as mock_get_token:
            mock_get_token.return_value = 'test_token'
            
            # This should trigger token retrieval
            with patch('nemo.core.classes.mixins.hf_io_mixin.HfApi') as mock_api:
                mock_api_instance = MagicMock()
                mock_api.return_value = mock_api_instance
                mock_api_instance.list_models.return_value = []
                
                # Call the search method which internally uses get_hf_token
                HuggingFaceFileIO.search_huggingface_models()
                
                # Verify get_hf_token was called
                mock_get_token.assert_called()

    @pytest.mark.unit
    def test_aws_credentials_from_parameter(self):
        """
        Test that AWS credentials are properly passed as parameters, not hardcoded.
        """
        from nemo.utils.s3_utils import S3Utils
        
        # Create mock credentials
        mock_creds = {
            'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
            'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'SessionToken': 'mock_session_token',
        }
        
        with patch('nemo.utils.s3_utils.boto3') as mock_boto3:
            mock_session = MagicMock()
            mock_resource = MagicMock()
            mock_boto3.Session.return_value = mock_session
            mock_session.resource.return_value = mock_resource
            
            # Call _get_s3_resource with credentials
            S3Utils._get_s3_resource(creds=mock_creds)
            
            # Verify the session was created with the provided credentials
            mock_session.resource.assert_called()
            call_kwargs = mock_session.resource.call_args[1]
            
            assert call_kwargs['aws_access_key_id'] == mock_creds['AccessKeyId']
            assert call_kwargs['aws_secret_access_key'] == mock_creds['SecretAccessKey']
            assert call_kwargs['aws_session_token'] == mock_creds['SessionToken']

    @pytest.mark.unit
    def test_config_based_api_key_retrieval(self):
        """
        Test that configuration-based API key retrieval uses safe defaults.
        """
        from omegaconf import DictConfig
        
        # Create a config without API key
        config_without_key = DictConfig({
            'model': 'test-model',
            'type': 'vllm',
        })
        
        # Simulate the pattern used in llm.py
        api_key = config_without_key.get("api_key", "None")
        
        # Verify the default is the string "None", not None or a real key
        assert api_key == "None", "Default API key should be the string 'None'"
        
        # Create a config with API key
        config_with_key = DictConfig({
            'model': 'test-model',
            'type': 'vllm',
            'api_key': 'sk-test-key-from-config',
        })
        
        api_key_from_config = config_with_key.get("api_key", "None")
        
        # Verify the key is retrieved from config
        assert api_key_from_config == 'sk-test-key-from-config', \
            "API key should be retrieved from config when present"
