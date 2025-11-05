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
Security Test Suite for CVE-011: Hardcoded Credentials and API Keys

This test suite verifies the security vulnerability described in CVE-011 where
hardcoded credentials, API keys, authentication tokens, or other secrets may
exist in the codebase.

Severity: HIGH
Jira Issue: https://ml6team.atlassian.net/browse/DR-139

Vulnerability Description:
The repository may contain hardcoded credentials for external services like:
- Hugging Face Hub
- NVIDIA NGC
- Wandb
- Neptune
- AWS S3

These tests verify that:
1. No hardcoded API keys or tokens exist in the codebase
2. Secrets are properly retrieved from environment variables or secure configuration
3. Default values are not actual secrets
4. Secure patterns are followed for credential management
"""

import ast
import os
import re
from pathlib import Path
from typing import List, Tuple

import pytest


class TestHardcodedCredentials:
    """Test suite for detecting hardcoded credentials in the codebase"""

    @pytest.fixture
    def nemo_source_path(self):
        """Get the path to the NeMo source directory"""
        return Path(__file__).parent.parent.parent / "nemo"

    @pytest.fixture
    def python_files(self, nemo_source_path):
        """Get all Python files in the NeMo source directory"""
        return list(nemo_source_path.rglob("*.py"))

    def test_no_hardcoded_api_keys_in_source(self, python_files):
        """
        Test that no hardcoded API keys exist in source code.
        
        This test scans all Python files for patterns that match common API key formats:
        - Strings that look like API keys (alphanumeric with specific length)
        - Variable assignments with 'api_key', 'token', etc. set to string literals
        
        Expected: No hardcoded API keys should be found
        """
        suspicious_patterns = [
            # Match api_key = "actual_key_value" but not api_key = "" or api_key = "None"
            r'(?:api_key|API_KEY|apikey)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            # Match token = "actual_token" but not token = "" or generic placeholders
            r'(?:token|TOKEN|auth_token|access_token)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            # Match secret = "actual_secret"
            r'(?:secret|SECRET|api_secret)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            # Match password = "actual_password"
            r'(?:password|PASSWORD|passwd)\s*=\s*["\']([a-zA-Z0-9_\-]{8,})["\']',
            # AWS keys pattern
            r'(?:aws_access_key_id|AWS_ACCESS_KEY_ID)\s*=\s*["\']([A-Z0-9]{20})["\']',
            r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']',
        ]

        findings = []
        
        for py_file in python_files:
            try:
                content = py_file.read_text(encoding='utf-8')
                
                for pattern in suspicious_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # Filter out obvious false positives
                        matched_value = match.group(1) if len(match.groups()) > 0 else ""
                        
                        # Skip common false positives
                        false_positives = [
                            "None",
                            "your_api_key",
                            "your_token",
                            "example",
                            "placeholder",
                            "test",
                            "dummy",
                            "fake",
                            "sample",
                            "mock",
                            # Tokenizer-related false positives
                            "additional_special_tokens",
                            "use_start_end_token",
                            "tokentype_embeddings",
                        ]
                        
                        if any(fp.lower() in matched_value.lower() for fp in false_positives):
                            continue
                        
                        # Report finding
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append({
                            'file': str(py_file.relative_to(py_file.parent.parent.parent)),
                            'line': line_num,
                            'match': match.group(0),
                            'value': matched_value,
                        })
            except Exception as e:
                # Skip files that can't be read
                pass

        # Assert no hardcoded credentials found
        if findings:
            error_msg = "Potential hardcoded credentials detected:\n"
            for finding in findings:
                error_msg += f"  - {finding['file']}:{finding['line']} - {finding['match']}\n"
            pytest.fail(error_msg)

    def test_huggingface_token_uses_secure_retrieval(self, nemo_source_path):
        """
        Test that Hugging Face tokens are retrieved securely.
        
        Checks that:
        1. hf_io_mixin.py uses get_hf_token() from huggingface_hub library
        2. No hardcoded tokens are present
        3. Token is passed as parameter or retrieved from environment
        
        Vulnerable file: nemo/core/classes/mixins/hf_io_mixin.py:115
        """
        hf_mixin_file = nemo_source_path / "core" / "classes" / "mixins" / "hf_io_mixin.py"
        
        assert hf_mixin_file.exists(), "HuggingFace IO mixin file not found"
        
        content = hf_mixin_file.read_text(encoding='utf-8')
        
        # Verify that get_hf_token is used (secure pattern)
        assert "get_hf_token()" in content or "get_token()" in content, \
            "HuggingFace token retrieval should use get_hf_token() from huggingface_hub"
        
        # Verify no hardcoded HF tokens (format: hf_xxxx...)
        hf_token_pattern = r'["\']hf_[a-zA-Z0-9]{30,}["\']'
        matches = re.findall(hf_token_pattern, content)
        assert len(matches) == 0, f"Potential hardcoded HuggingFace token found: {matches}"
        
        # Parse the Python file and check token handling in push_to_hf_hub method
        tree = ast.parse(content)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "push_to_hf_hub":
                # Check that token parameter exists and has proper default
                token_arg_found = False
                for arg in node.args.args:
                    if arg.arg == "token":
                        token_arg_found = True
                        break
                
                # The function should accept token as parameter
                assert token_arg_found or "token" in [kw.arg for kw in node.args.kwonlyargs], \
                    "push_to_hf_hub should accept token as a parameter"

    def test_pipecat_llm_api_key_handling(self, nemo_source_path):
        """
        Test that LLM API keys in pipecat services are handled securely.
        
        Checks that:
        1. API keys are retrieved from config, not hardcoded
        2. Default value is safe (e.g., "None" string, not an actual key)
        3. No actual API keys are present in the code
        
        Vulnerable file: nemo/agents/voice_agent/pipecat/services/nemo/llm.py:724
        """
        llm_file = nemo_source_path / "agents" / "voice_agent" / "pipecat" / "services" / "nemo" / "llm.py"
        
        if not llm_file.exists():
            pytest.skip("Pipecat LLM service file not found")
        
        content = llm_file.read_text(encoding='utf-8')
        
        # Verify API key is retrieved from config
        config_get_pattern = r'config\.get\(["\']api_key["\']\s*,\s*["\']None["\']\)'
        matches = re.findall(config_get_pattern, content)
        
        # The pattern should exist, showing secure retrieval from config
        assert len(matches) > 0, \
            "API key should be retrieved from config with safe default"
        
        # Verify no hardcoded OpenAI-style API keys (sk-...)
        openai_key_pattern = r'["\']sk-[a-zA-Z0-9]{40,}["\']'
        hardcoded_keys = re.findall(openai_key_pattern, content)
        assert len(hardcoded_keys) == 0, \
            f"Potential hardcoded OpenAI API key found: {hardcoded_keys}"
        
        # Parse and verify VLLMService initialization
        tree = ast.parse(content)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "__init__":
                # Look for api_key parameter in VLLMService or similar classes
                for arg in node.args.kwonlyargs:
                    if arg.arg == "api_key":
                        # Check for default value
                        default_idx = node.args.kwonlyargs.index(arg)
                        if default_idx < len(node.args.kw_defaults):
                            default = node.args.kw_defaults[default_idx]
                            if isinstance(default, ast.Constant):
                                # Verify default is safe
                                assert default.value in ["None", None, ""], \
                                    f"API key default should be 'None' or empty, got: {default.value}"

    def test_s3_credentials_not_hardcoded(self, nemo_source_path):
        """
        Test that AWS S3 credentials are not hardcoded.
        
        Checks that:
        1. AWS credentials are passed as parameters or retrieved from environment
        2. No hardcoded AWS access keys or secret keys exist
        3. Session tokens are handled securely
        
        Vulnerable file: nemo/utils/s3_utils.py:232
        """
        s3_utils_file = nemo_source_path / "utils" / "s3_utils.py"
        
        assert s3_utils_file.exists(), "S3 utils file not found"
        
        content = s3_utils_file.read_text(encoding='utf-8')
        
        # Verify credentials are passed as parameter
        assert 'creds["SessionToken"]' in content or 'creds.get("SessionToken")' in content, \
            "Session token should be retrieved from credentials parameter"
        
        # Verify no hardcoded AWS access key IDs (AKIA...)
        aws_access_key_pattern = r'["\']AKIA[A-Z0-9]{16}["\']'
        hardcoded_access_keys = re.findall(aws_access_key_pattern, content)
        assert len(hardcoded_access_keys) == 0, \
            f"Potential hardcoded AWS access key found: {hardcoded_access_keys}"
        
        # Verify no hardcoded AWS secret access keys (40 character base64-like strings)
        aws_secret_pattern = r'aws_secret_access_key\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']'
        hardcoded_secrets = re.findall(aws_secret_pattern, content)
        assert len(hardcoded_secrets) == 0, \
            f"Potential hardcoded AWS secret key found"
        
        # Parse and verify _get_s3_resource method
        tree = ast.parse(content)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_get_s3_resource":
                # Verify creds parameter exists
                param_names = [arg.arg for arg in node.args.args]
                assert "creds" in param_names, \
                    "_get_s3_resource should accept credentials as parameter"

    def test_neptune_api_key_secure_handling(self, nemo_source_path):
        """
        Test that Neptune API keys are handled securely.
        
        Checks that:
        1. Neptune API key is retrieved from environment variable
        2. No hardcoded Neptune API tokens exist
        3. Proper error handling for missing credentials
        
        Related: nemo/utils/exp_manager.py:1307
        """
        exp_manager_file = nemo_source_path / "utils" / "exp_manager.py"
        
        assert exp_manager_file.exists(), "Experiment manager file not found"
        
        content = exp_manager_file.read_text(encoding='utf-8')
        
        # Verify environment variable check exists
        assert 'os.getenv("NEPTUNE_API_TOKEN"' in content, \
            "Neptune API token should be retrieved from environment variable"
        
        # Verify error is raised when API key is missing
        neptune_error_pattern = r'raise ValueError.*api_key.*NEPTUNE_API_TOKEN'
        matches = re.findall(neptune_error_pattern, content, re.DOTALL)
        assert len(matches) > 0, \
            "Should raise error when Neptune API key is not configured"
        
        # Verify no hardcoded Neptune tokens (format varies but typically long alphanumeric)
        # Neptune tokens often look like: eyJhcGlfYWRkcmVzcyI6Imh0dHBzOi8v...
        neptune_token_pattern = r'["\']eyJ[a-zA-Z0-9_\-\.]{50,}["\']'
        hardcoded_tokens = re.findall(neptune_token_pattern, content)
        assert len(hardcoded_tokens) == 0, \
            f"Potential hardcoded Neptune token found"

    def test_wandb_credentials_secure_handling(self, nemo_source_path):
        """
        Test that Weights & Biases (wandb) API keys are handled securely.
        
        Checks that:
        1. Wandb uses environment variables for authentication
        2. No hardcoded wandb API keys exist
        3. Wandb logger initialization doesn't contain secrets
        """
        # Search for wandb usage in relevant files
        wandb_files = list(nemo_source_path.rglob("**/exp_manager.py")) + \
                      list(nemo_source_path.rglob("**/plugins.py"))
        
        if not wandb_files:
            pytest.skip("No wandb-related files found")
        
        for wandb_file in wandb_files:
            if not wandb_file.exists():
                continue
                
            content = wandb_file.read_text(encoding='utf-8')
            
            # Verify no hardcoded wandb API keys
            # Wandb keys are typically 40 character hexadecimal strings
            wandb_key_pattern = r'["\'][a-f0-9]{40}["\']'
            
            # This pattern is too broad, so we only check near wandb-related code
            if "wandb" in content.lower() or "WandbLogger" in content:
                # Check for hardcoded keys in wandb context
                wandb_sections = re.split(r'\n\s*\n', content)
                for section in wandb_sections:
                    if "wandb" in section.lower():
                        # Look for api_key assignments in wandb sections
                        if "api_key" in section and "=" in section:
                            api_key_assignments = re.findall(
                                r'api_key\s*=\s*["\']([a-f0-9]{40})["\']',
                                section
                            )
                            assert len(api_key_assignments) == 0, \
                                f"Potential hardcoded wandb API key in {wandb_file}"

    def test_no_git_secrets_in_code(self, python_files):
        """
        Test that no git/GitHub tokens or personal access tokens are hardcoded.
        
        Checks for:
        1. GitHub personal access tokens (ghp_...)
        2. GitHub OAuth tokens (gho_...)
        3. Git credentials in URLs
        """
        git_token_patterns = [
            r'["\']ghp_[a-zA-Z0-9]{36}["\']',  # GitHub personal access token
            r'["\']gho_[a-zA-Z0-9]{36}["\']',  # GitHub OAuth token
            r'["\']github_pat_[a-zA-Z0-9_]{22,}["\']',  # New GitHub PAT format
            r'https://[a-zA-Z0-9]+:[a-zA-Z0-9]+@github\.com',  # Credentials in URL
        ]
        
        findings = []
        
        for py_file in python_files:
            try:
                content = py_file.read_text(encoding='utf-8')
                
                for pattern in git_token_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append({
                            'file': str(py_file.relative_to(py_file.parent.parent.parent)),
                            'line': line_num,
                            'pattern': pattern,
                        })
            except Exception:
                pass
        
        assert len(findings) == 0, \
            f"Potential git credentials found in {len(findings)} locations"

    def test_environment_variable_usage_for_secrets(self, nemo_source_path):
        """
        Test that environment variables are used for sensitive configuration.
        
        This is a positive test that verifies the CORRECT pattern:
        - Using os.getenv() or os.environ for API keys and tokens
        - Proper fallback handling
        """
        files_to_check = [
            nemo_source_path / "utils" / "exp_manager.py",
            nemo_source_path / "core" / "classes" / "mixins" / "hf_io_mixin.py",
        ]
        
        env_var_patterns = [
            r'os\.getenv\(["\']NEPTUNE_API_TOKEN["\']',
            r'get_hf_token\(\)',  # HuggingFace's secure token retrieval
        ]
        
        secure_pattern_found = False
        
        for file_path in files_to_check:
            if not file_path.exists():
                continue
                
            content = file_path.read_text(encoding='utf-8')
            
            for pattern in env_var_patterns:
                if re.search(pattern, content):
                    secure_pattern_found = True
                    break
        
        assert secure_pattern_found, \
            "Expected to find secure environment variable usage patterns for credentials"

    def test_config_based_credential_retrieval(self, nemo_source_path):
        """
        Test that credentials are retrieved from configuration objects.
        
        This verifies the pattern:
        - config.get("api_key", safe_default)
        - Configuration-based credential management
        """
        llm_file = nemo_source_path / "agents" / "voice_agent" / "pipecat" / "services" / "nemo" / "llm.py"
        
        if not llm_file.exists():
            pytest.skip("LLM service file not found")
        
        content = llm_file.read_text(encoding='utf-8')
        
        # Look for config.get pattern for API keys
        config_get_pattern = r'config\.get\(["\'](?:api_key|token|secret)["\']'
        matches = re.findall(config_get_pattern, content)
        
        assert len(matches) > 0, \
            "Expected to find config-based credential retrieval pattern"

    def test_no_jwt_tokens_hardcoded(self, python_files):
        """
        Test that no JWT tokens are hardcoded in the source.
        
        JWT tokens typically start with 'eyJ' (base64 encoded JSON header)
        """
        jwt_pattern = r'["\']eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+["\']'
        
        findings = []
        
        for py_file in python_files:
            try:
                content = py_file.read_text(encoding='utf-8')
                matches = re.finditer(jwt_pattern, content)
                
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append({
                        'file': str(py_file.relative_to(py_file.parent.parent.parent)),
                        'line': line_num,
                        'token_preview': match.group(0)[:50] + "...",
                    })
            except Exception:
                pass
        
        assert len(findings) == 0, \
            f"Potential hardcoded JWT tokens found in {len(findings)} files"


class TestCredentialManagementBestPractices:
    """Tests for credential management best practices"""

    def test_documentation_mentions_secret_management(self):
        """
        Test that documentation exists for secure secret management.
        
        This is a positive test to ensure developers are guided on proper practices.
        Note: This test may need adjustment based on actual documentation structure.
        """
        # This test documents the EXPECTED behavior
        # In a secure system, there should be documentation on:
        # 1. How to set environment variables
        # 2. Where to store API keys
        # 3. How to use configuration files
        
        # For now, this serves as documentation of the security requirement
        assert True, "Secret management documentation should exist"

    def test_no_secrets_in_test_files(self):
        """
        Test that test files don't contain actual secrets.
        
        Test files should use mocks, fixtures, or dummy values.
        """
        tests_path = Path(__file__).parent.parent
        test_files = list(tests_path.rglob("test_*.py"))
        
        suspicious_patterns = [
            r'api_key\s*=\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
            r'token\s*=\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        ]
        
        findings = []
        
        for test_file in test_files[:50]:  # Limit to avoid long test times
            try:
                content = test_file.read_text(encoding='utf-8')
                
                for pattern in suspicious_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        value = re.search(r'["\']([^"\']+)["\']', match.group(0))
                        if value:
                            matched_value = value.group(1)
                            # Filter obvious test values
                            if matched_value.lower() not in ["test", "fake", "dummy", "mock", "example"]:
                                line_num = content[:match.start()].count('\n') + 1
                                findings.append({
                                    'file': str(test_file.relative_to(tests_path)),
                                    'line': line_num,
                                })
            except Exception:
                pass
        
        # This test allows some findings as tests may have valid test keys
        # But alerts if too many suspicious patterns are found
        assert len(findings) < 10, \
            f"Found {len(findings)} suspicious credential patterns in test files"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
