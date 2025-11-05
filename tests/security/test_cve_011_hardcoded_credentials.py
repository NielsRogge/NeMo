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

This test suite validates that the codebase does not contain hardcoded credentials,
API keys, tokens, or other secrets that could compromise security.

Vulnerability Details:
- CVE ID: CVE-011
- Title: Hardcoded Credentials and API Keys
- Severity: HIGH
- Description: The repository may contain hardcoded credentials for external services
  like Hugging Face Hub, NVIDIA NGC, and Wandb.
"""

import os
import re
from pathlib import Path
from typing import List, Tuple

import pytest


# Test data directories and files to exclude from scanning
EXCLUDE_DIRS = {
    '.git',
    '__pycache__',
    '.pytest_cache',
    'node_modules',
    '.tox',
    '.venv',
    'venv',
    'build',
    'dist',
    '.eggs',
}

EXCLUDE_PATTERNS = {
    '*.pyc',
    '*.pyo',
    '*.so',
    '*.dylib',
    '*.dll',
    '*.egg-info',
    '*.whl',
}

# Patterns that indicate potential hardcoded credentials
# These patterns are designed to catch common credential formats
CREDENTIAL_PATTERNS = [
    # API keys (various formats)
    (r'api[_-]?key\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Potential hardcoded API key'),
    (r'apikey\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Potential hardcoded API key'),
    
    # Access tokens (various formats)
    (r'access[_-]?token\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Potential hardcoded access token'),
    (r'auth[_-]?token\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Potential hardcoded auth token'),
    
    # Bearer tokens
    (r'bearer\s+([a-zA-Z0-9_\-\.]{20,})', 'Potential hardcoded bearer token'),
    
    # AWS credentials
    (r'aws[_-]?secret[_-]?access[_-]?key\s*=\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'Potential hardcoded AWS secret key'),
    (r'aws[_-]?access[_-]?key[_-]?id\s*=\s*["\']([A-Z0-9]{20})["\']', 'Potential hardcoded AWS access key'),
    
    # HuggingFace tokens (format: hf_XXXX)
    (r'hf_[a-zA-Z0-9]{34,}', 'Potential hardcoded HuggingFace token'),
    
    # GitHub tokens (format: ghp_XXXX, gho_XXXX, etc.)
    (r'gh[ps]_[a-zA-Z0-9]{36,}', 'Potential hardcoded GitHub token'),
    
    # Generic secrets
    (r'secret\s*=\s*["\']([a-zA-Z0-9_\-+/=]{20,})["\']', 'Potential hardcoded secret'),
    
    # Passwords
    (r'password\s*=\s*["\'](?!.*(\$|\{|<|>|your|pass|pwd|changeme|test|dummy|example|xxx))[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:,./<>?]{8,}["\']', 'Potential hardcoded password'),
]

# Safe patterns that should be excluded from findings (false positives)
SAFE_PATTERNS = [
    r'["\']xxx+["\']',  # Placeholder like "xxxx" or "xxxxxxx"
    r'["\']<.*>["\']',  # Placeholder like "<WANDB_KEY>" or "<HF_TOKEN>"
    r'["\']your[_-]',  # Placeholder like "your_api_key"
    r'["\']test[_-]',  # Test placeholder
    r'["\']dummy',     # Dummy placeholder
    r'["\']example',   # Example placeholder
    r'["\']changeme["\']',  # Changeme placeholder
    r'["\']TODO["\']',  # TODO placeholder
    r'["\']FIXME["\']', # FIXME placeholder
    r'["\']["\']',      # Empty string
    r'["\']\s*["\']',   # Empty or whitespace string
    r'os\.environ',     # Environment variable access
    r'getenv',          # Environment variable getter
    r'config\.get',     # Configuration getter
]


def should_exclude_path(path: Path) -> bool:
    """Check if a path should be excluded from scanning."""
    # Exclude directories
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return True
    
    # Exclude by pattern
    for pattern in EXCLUDE_PATTERNS:
        if path.match(pattern):
            return True
    
    return False


def is_safe_match(line: str, match: str) -> bool:
    """Check if a match is a false positive (safe pattern)."""
    for pattern in SAFE_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False


def scan_file_for_credentials(file_path: Path) -> List[Tuple[int, str, str, str]]:
    """
    Scan a single file for potential hardcoded credentials.
    
    Returns:
        List of tuples (line_number, line_content, matched_text, pattern_description)
    """
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Skip comments (basic check)
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('//'):
                    # Allow scanning comments for actual credentials but skip obvious placeholders
                    pass
                
                for pattern, description in CREDENTIAL_PATTERNS:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        matched_text = match.group(0)
                        
                        # Check if this is a safe/expected pattern
                        if not is_safe_match(line, matched_text):
                            findings.append((line_num, line.strip(), matched_text, description))
    
    except Exception as e:
        # Skip files that can't be read
        pass
    
    return findings


def scan_codebase(base_path: Path) -> dict:
    """
    Scan the entire codebase for hardcoded credentials.
    
    Returns:
        Dictionary mapping file paths to their findings
    """
    results = {}
    
    # Scan Python files
    for py_file in base_path.rglob('*.py'):
        if should_exclude_path(py_file):
            continue
        
        findings = scan_file_for_credentials(py_file)
        if findings:
            results[str(py_file.relative_to(base_path))] = findings
    
    # Scan YAML/YML configuration files
    for yaml_file in list(base_path.rglob('*.yaml')) + list(base_path.rglob('*.yml')):
        if should_exclude_path(yaml_file):
            continue
        
        findings = scan_file_for_credentials(yaml_file)
        if findings:
            results[str(yaml_file.relative_to(base_path))] = findings
    
    # Scan JSON configuration files
    for json_file in base_path.rglob('*.json'):
        if should_exclude_path(json_file):
            continue
        
        findings = scan_file_for_credentials(json_file)
        if findings:
            results[str(json_file.relative_to(base_path))] = findings
    
    return results


@pytest.fixture(scope="module")
def workspace_path():
    """Get the workspace root path."""
    return Path(__file__).parent.parent.parent


@pytest.fixture(scope="module")
def scan_results(workspace_path):
    """Scan the codebase for hardcoded credentials (cached for all tests)."""
    return scan_codebase(workspace_path)


class TestHardcodedCredentials:
    """Test suite for detecting hardcoded credentials."""
    
    def test_no_hardcoded_api_keys(self, scan_results):
        """Test that no hardcoded API keys are present in the codebase."""
        api_key_findings = {}
        
        for file_path, findings in scan_results.items():
            for line_num, line, matched_text, description in findings:
                if 'api' in description.lower() and 'key' in description.lower():
                    if file_path not in api_key_findings:
                        api_key_findings[file_path] = []
                    api_key_findings[file_path].append((line_num, line, matched_text, description))
        
        # Generate detailed failure message
        if api_key_findings:
            msg = "\n\nFound potential hardcoded API keys:\n"
            for file_path, findings in api_key_findings.items():
                msg += f"\n{file_path}:\n"
                for line_num, line, matched_text, description in findings:
                    msg += f"  Line {line_num}: {description}\n"
                    msg += f"    {line}\n"
                    msg += f"    Matched: {matched_text}\n"
            
            pytest.fail(msg)
    
    def test_no_hardcoded_tokens(self, scan_results):
        """Test that no hardcoded access tokens are present in the codebase."""
        token_findings = {}
        
        for file_path, findings in scan_results.items():
            for line_num, line, matched_text, description in findings:
                if 'token' in description.lower():
                    if file_path not in token_findings:
                        token_findings[file_path] = []
                    token_findings[file_path].append((line_num, line, matched_text, description))
        
        # Generate detailed failure message
        if token_findings:
            msg = "\n\nFound potential hardcoded tokens:\n"
            for file_path, findings in token_findings.items():
                msg += f"\n{file_path}:\n"
                for line_num, line, matched_text, description in findings:
                    msg += f"  Line {line_num}: {description}\n"
                    msg += f"    {line}\n"
                    msg += f"    Matched: {matched_text}\n"
            
            pytest.fail(msg)
    
    def test_no_hardcoded_passwords(self, scan_results):
        """Test that no hardcoded passwords are present in the codebase."""
        password_findings = {}
        
        for file_path, findings in scan_results.items():
            for line_num, line, matched_text, description in findings:
                if 'password' in description.lower():
                    if file_path not in password_findings:
                        password_findings[file_path] = []
                    password_findings[file_path].append((line_num, line, matched_text, description))
        
        # Generate detailed failure message
        if password_findings:
            msg = "\n\nFound potential hardcoded passwords:\n"
            for file_path, findings in password_findings.items():
                msg += f"\n{file_path}:\n"
                for line_num, line, matched_text, description in findings:
                    msg += f"  Line {line_num}: {description}\n"
                    msg += f"    {line}\n"
                    msg += f"    Matched: {matched_text}\n"
            
            pytest.fail(msg)
    
    def test_no_hardcoded_aws_credentials(self, scan_results):
        """Test that no hardcoded AWS credentials are present in the codebase."""
        aws_findings = {}
        
        for file_path, findings in scan_results.items():
            for line_num, line, matched_text, description in findings:
                if 'aws' in description.lower():
                    if file_path not in aws_findings:
                        aws_findings[file_path] = []
                    aws_findings[file_path].append((line_num, line, matched_text, description))
        
        # Generate detailed failure message
        if aws_findings:
            msg = "\n\nFound potential hardcoded AWS credentials:\n"
            for file_path, findings in aws_findings.items():
                msg += f"\n{file_path}:\n"
                for line_num, line, matched_text, description in findings:
                    msg += f"  Line {line_num}: {description}\n"
                    msg += f"    {line}\n"
                    msg += f"    Matched: {matched_text}\n"
            
            pytest.fail(msg)
    
    def test_no_hardcoded_huggingface_tokens(self, scan_results):
        """Test that no hardcoded HuggingFace tokens are present in the codebase."""
        hf_findings = {}
        
        for file_path, findings in scan_results.items():
            for line_num, line, matched_text, description in findings:
                if 'huggingface' in description.lower() or matched_text.startswith('hf_'):
                    if file_path not in hf_findings:
                        hf_findings[file_path] = []
                    hf_findings[file_path].append((line_num, line, matched_text, description))
        
        # Generate detailed failure message
        if hf_findings:
            msg = "\n\nFound potential hardcoded HuggingFace tokens:\n"
            for file_path, findings in hf_findings.items():
                msg += f"\n{file_path}:\n"
                for line_num, line, matched_text, description in findings:
                    msg += f"  Line {line_num}: {description}\n"
                    msg += f"    {line}\n"
                    msg += f"    Matched: {matched_text}\n"
            
            pytest.fail(msg)
    
    def test_no_hardcoded_github_tokens(self, scan_results):
        """Test that no hardcoded GitHub tokens are present in the codebase."""
        gh_findings = {}
        
        for file_path, findings in scan_results.items():
            for line_num, line, matched_text, description in findings:
                if 'github' in description.lower() or matched_text.startswith(('ghp_', 'gho_', 'ghs_')):
                    if file_path not in gh_findings:
                        gh_findings[file_path] = []
                    gh_findings[file_path].append((line_num, line, matched_text, description))
        
        # Generate detailed failure message
        if gh_findings:
            msg = "\n\nFound potential hardcoded GitHub tokens:\n"
            for file_path, findings in gh_findings.items():
                msg += f"\n{file_path}:\n"
                for line_num, line, matched_text, description in findings:
                    msg += f"  Line {line_num}: {description}\n"
                    msg += f"    {line}\n"
                    msg += f"    Matched: {matched_text}\n"
            
            pytest.fail(msg)
    
    def test_no_generic_hardcoded_secrets(self, scan_results):
        """Test that no generic hardcoded secrets are present in the codebase."""
        secret_findings = {}
        
        for file_path, findings in scan_results.items():
            for line_num, line, matched_text, description in findings:
                if 'secret' in description.lower():
                    # Skip AWS secrets (already tested separately)
                    if 'aws' in description.lower():
                        continue
                    
                    if file_path not in secret_findings:
                        secret_findings[file_path] = []
                    secret_findings[file_path].append((line_num, line, matched_text, description))
        
        # Generate detailed failure message
        if secret_findings:
            msg = "\n\nFound potential hardcoded secrets:\n"
            for file_path, findings in secret_findings.items():
                msg += f"\n{file_path}:\n"
                for line_num, line, matched_text, description in findings:
                    msg += f"  Line {line_num}: {description}\n"
                    msg += f"    {line}\n"
                    msg += f"    Matched: {matched_text}\n"
            
            pytest.fail(msg)
    
    def test_credential_handling_uses_env_vars(self, workspace_path):
        """Test that credential handling code uses environment variables."""
        # Check specific files that handle credentials
        files_to_check = [
            workspace_path / "nemo" / "core" / "classes" / "mixins" / "hf_io_mixin.py",
            workspace_path / "nemo" / "agents" / "voice_agent" / "pipecat" / "services" / "nemo" / "llm.py",
            workspace_path / "nemo" / "utils" / "s3_utils.py",
        ]
        
        issues = []
        
        for file_path in files_to_check:
            if not file_path.exists():
                continue
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Check for proper token/credential handling patterns
                has_env_access = any(pattern in content for pattern in [
                    'os.environ',
                    'getenv',
                    'get_token(',
                    'config.get('
                ])
                
                # Check for hardcoded patterns (simplified check)
                has_hardcoded = re.search(
                    r'(api_key|token|secret)\s*=\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
                    content,
                    re.IGNORECASE
                )
                
                if has_hardcoded and not has_env_access:
                    issues.append(f"{file_path.name}: Appears to hardcode credentials without environment variable fallback")
        
        if issues:
            pytest.fail("\n\nCredential handling issues:\n" + "\n".join(f"  - {issue}" for issue in issues))
    
    def test_total_findings_summary(self, scan_results):
        """Provide a summary of all findings (informational test)."""
        if not scan_results:
            # This is good - no findings
            return
        
        total_findings = sum(len(findings) for findings in scan_results.values())
        files_with_findings = len(scan_results)
        
        # Generate summary message
        msg = f"\n\nSecurity Scan Summary:"
        msg += f"\n  Files with potential issues: {files_with_findings}"
        msg += f"\n  Total potential credential findings: {total_findings}"
        msg += f"\n\nDetailed findings:\n"
        
        for file_path, findings in scan_results.items():
            msg += f"\n{file_path} ({len(findings)} finding(s)):\n"
            for line_num, line, matched_text, description in findings:
                msg += f"  Line {line_num}: {description}\n"
                msg += f"    {line[:100]}{'...' if len(line) > 100 else ''}\n"
        
        # This test fails if there are any findings
        if total_findings > 0:
            pytest.fail(msg)


class TestSecureCredentialPatterns:
    """Test suite for verifying secure credential handling patterns."""
    
    def test_huggingface_token_from_function(self, workspace_path):
        """Test that HuggingFace token access uses the get_hf_token() function."""
        hf_io_mixin = workspace_path / "nemo" / "core" / "classes" / "mixins" / "hf_io_mixin.py"
        
        if not hf_io_mixin.exists():
            pytest.skip("HuggingFace IO mixin file not found")
        
        with open(hf_io_mixin, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Verify that get_hf_token() is imported and used
        assert 'from huggingface_hub import get_token as get_hf_token' in content, \
            "get_hf_token should be imported from huggingface_hub"
        
        assert 'get_hf_token()' in content, \
            "get_hf_token() function should be called to retrieve tokens"
        
        # Ensure no hardcoded token patterns
        hardcoded_pattern = re.compile(r'hf_token\s*=\s*["\'][a-zA-Z0-9_\-]{34,}["\']')
        matches = hardcoded_pattern.findall(content)
        
        assert not matches, f"Found potential hardcoded HF tokens: {matches}"
    
    def test_api_keys_from_config(self, workspace_path):
        """Test that API keys are retrieved from configuration, not hardcoded."""
        llm_file = workspace_path / "nemo" / "agents" / "voice_agent" / "pipecat" / "services" / "nemo" / "llm.py"
        
        if not llm_file.exists():
            pytest.skip("LLM service file not found")
        
        with open(llm_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Verify that API keys are retrieved from config
        assert 'config.get(' in content, \
            "API keys should be retrieved using config.get()"
        
        # Check that default values are safe (not actual keys)
        unsafe_defaults = re.findall(
            r'config\.get\(["\']api_key["\'],\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            content
        )
        
        # Filter out safe placeholder values
        unsafe_defaults = [
            default for default in unsafe_defaults
            if default not in ['None', 'none', 'test', 'dummy', 'example']
            and not default.startswith('xxx')
            and not default.startswith('<')
        ]
        
        assert not unsafe_defaults, \
            f"Found potentially unsafe default API key values: {unsafe_defaults}"
    
    def test_aws_credentials_from_parameters(self, workspace_path):
        """Test that AWS credentials are passed as parameters, not hardcoded."""
        s3_utils = workspace_path / "nemo" / "utils" / "s3_utils.py"
        
        if not s3_utils.exists():
            pytest.skip("S3 utils file not found")
        
        with open(s3_utils, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check that credentials are passed as parameters
        assert 'creds:' in content or 'creds[' in content, \
            "AWS credentials should be passed as parameters"
        
        # Ensure no hardcoded AWS access keys
        hardcoded_aws_pattern = re.compile(
            r'(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][A-Za-z0-9/+=]{20,}["\']'
        )
        matches = hardcoded_aws_pattern.findall(content)
        
        assert not matches, f"Found potential hardcoded AWS credentials: {matches}"
    
    def test_environment_variable_usage(self, workspace_path):
        """Test that the codebase properly uses environment variables for secrets."""
        # Sample files that should use environment variables
        files_to_check = [
            "nemo/lightning/run/plugins.py",
            "nemo/collections/common/parts/skills_utils.py",
        ]
        
        env_usage = {}
        
        for file_rel_path in files_to_check:
            file_path = workspace_path / file_rel_path
            if not file_path.exists():
                continue
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Count environment variable accesses
            env_patterns = [
                len(re.findall(r'os\.environ\[', content)),
                len(re.findall(r'os\.environ\.get\(', content)),
                len(re.findall(r'os\.getenv\(', content)),
            ]
            
            env_usage[file_rel_path] = sum(env_patterns)
        
        # At least some files should use environment variables
        assert any(count > 0 for count in env_usage.values()), \
            "No environment variable usage detected in credential-handling files"
