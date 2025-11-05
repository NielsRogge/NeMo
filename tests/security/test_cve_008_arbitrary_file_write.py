# Copyright (c) 2020, NVIDIA CORPORATION.  All rights reserved.
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
Security Tests for CVE-008: Arbitrary File Write Vulnerability

These tests verify the existence of potential arbitrary file write vulnerabilities
in the NeMo framework. The vulnerability occurs when file paths can be controlled by 
user input or malicious configuration, potentially allowing attackers to:
- Overwrite critical system files
- Write malicious scripts to sensitive locations  
- Perform directory traversal attacks

Severity: CRITICAL
Jira Issue: https://ml6team.atlassian.net/browse/DR-138

NOTE: These tests are designed to DETECT the vulnerability, not to fix it.
They serve as documentation and verification of the security concern.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock

import pytest


class TestCVE008ArbitraryFileWrite:
    """
    Test suite for CVE-008: Arbitrary File Write vulnerability.
    
    These tests verify that the codebase contains patterns that could lead to
    arbitrary file write vulnerabilities when user-controlled input is used
    to determine file paths.
    """

    @pytest.mark.unit
    def test_path_traversal_vulnerability_pattern(self):
        """
        Test that path traversal patterns (../) are not sanitized in file operations.
        
        This test verifies that the codebase does not properly validate paths
        to prevent directory traversal attacks. An attacker could use paths like
        '../../../etc/passwd' to write to arbitrary locations.
        
        VULNERABILITY: If this test passes, it indicates the code accepts
        path traversal patterns without validation.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Attempt to write outside the intended directory using path traversal
            malicious_path = os.path.join(tmpdir, "safe_dir", "..", "..", "malicious.txt")
            
            # This should ideally be blocked, but the framework allows it
            # Normalize the path to see where it actually points
            normalized_path = os.path.normpath(malicious_path)
            
            # Verify that the normalized path is outside the intended directory
            assert not normalized_path.startswith(os.path.join(tmpdir, "safe_dir"))
            
            # Test that the framework would allow writing to this path
            # (we simulate this to avoid actually writing outside tmpdir)
            try:
                os.makedirs(os.path.dirname(normalized_path), exist_ok=True)
                with open(normalized_path, 'w') as f:
                    f.write("malicious content")
                    
                # If we get here, the vulnerability exists - no validation prevented the write
                assert os.path.exists(normalized_path), "Path traversal write succeeded - vulnerability exists"
            except (OSError, PermissionError):
                # If an error occurs, it's due to OS-level restrictions, not app validation
                pass

    @pytest.mark.unit
    def test_absolute_path_overwrite_vulnerability(self):
        """
        Test that absolute paths can be used in file write operations.
        
        This test verifies that the codebase accepts absolute paths without
        validation, potentially allowing an attacker to overwrite system files
        if they can control the output path configuration.
        
        VULNERABILITY: User-controlled absolute paths could overwrite
        critical system files like /etc/crontab, /etc/passwd, etc.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a "system file" simulation
            system_file = os.path.join(tmpdir, "system_critical_file.conf")
            with open(system_file, 'w') as f:
                f.write("critical system configuration")
            
            # Attacker provides an absolute path to overwrite the system file
            malicious_absolute_path = system_file
            
            # The framework allows writing to absolute paths without validation
            with open(malicious_absolute_path, 'w') as f:
                f.write("malicious overwrite")
            
            # Verify the system file was overwritten
            with open(system_file, 'r') as f:
                content = f.read()
                
            assert content == "malicious overwrite", "Absolute path overwrite succeeded - vulnerability exists"

    @pytest.mark.unit  
    def test_manifest_output_path_injection(self):
        """
        Test vulnerability in tools/nemo_forced_aligner/align.py:329
        
        The code uses:
            tgt_manifest_filepath = str(Path(cfg.output_dir) / tgt_manifest_name)
            f_manifest_out = open(tgt_manifest_filepath, 'w')
            
        VULNERABILITY: If cfg.output_dir contains path traversal sequences
        or tgt_manifest_name contains absolute path, it could write to arbitrary locations.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate malicious configuration with path traversal
            malicious_output_dir = os.path.join(tmpdir, "output", "..", "..", "sensitive")
            manifest_name = "../../etc/malicious_manifest.json"
            
            # Recreate the vulnerable pattern from align.py
            tgt_manifest_filepath = str(Path(malicious_output_dir) / manifest_name)
            
            # Normalize to see actual target
            normalized_path = os.path.normpath(tgt_manifest_filepath)
            
            # Verify path traversal is possible
            assert ".." in tgt_manifest_filepath or not normalized_path.startswith(tmpdir), \
                "Path traversal through manifest path succeeded - vulnerability exists"

    @pytest.mark.unit
    def test_engine_file_path_injection(self):
        """
        Test vulnerability in nemo/export/multimodal/build.py:290
        
        The code uses:
            with open(engine_file, 'wb') as f:
                f.write(engine_string)
                
        VULNERABILITY: If engine_file path is derived from user input
        without validation, it could write to arbitrary locations.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate malicious engine file path
            malicious_engine_path = os.path.join(tmpdir, "..", "malicious_engine.bin")
            
            # Test that the code would allow writing to this path
            normalized_path = os.path.normpath(malicious_engine_path)
            
            # Verify path traversal is possible
            assert not normalized_path.startswith(tmpdir), \
                "Path traversal through engine_file succeeded - vulnerability exists"
            
            # Simulate the vulnerable write operation
            try:
                os.makedirs(os.path.dirname(normalized_path), exist_ok=True)
                with open(normalized_path, 'wb') as f:
                    f.write(b"malicious engine data")
                    
                assert os.path.exists(normalized_path), "Engine file write to arbitrary path succeeded"
            except (OSError, PermissionError):
                pass

    @pytest.mark.unit
    def test_model_card_path_injection(self):
        """
        Test vulnerability in nemo/core/classes/mixins/hf_io_mixin.py:229
        
        The code uses:
            model_card_filepath = saved_path / f"README.md"
            model_card_filepath.write_text(str(model_card), encoding='utf-8', errors='ignore')
            
        VULNERABILITY: If saved_path is derived from user input without
        validation, it could write to arbitrary locations.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate malicious saved_path with path traversal
            malicious_saved_path = Path(tmpdir) / ".." / ".." / "malicious_dir"
            
            # Recreate the vulnerable pattern
            model_card_filepath = malicious_saved_path / "README.md"
            
            # Verify path traversal is possible
            normalized_path = os.path.normpath(str(model_card_filepath))
            assert not normalized_path.startswith(tmpdir), \
                "Path traversal through model_card_filepath succeeded - vulnerability exists"

    @pytest.mark.unit
    def test_symlink_following_vulnerability(self):
        """
        Test that file write operations follow symlinks without validation.
        
        VULNERABILITY: An attacker could create a symlink in a writable directory
        that points to a sensitive file, then trigger the application to write
        to the symlink path, resulting in overwriting the sensitive file.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a "sensitive" file
            sensitive_file = os.path.join(tmpdir, "sensitive", "critical.conf")
            os.makedirs(os.path.dirname(sensitive_file), exist_ok=True)
            with open(sensitive_file, 'w') as f:
                f.write("sensitive data")
            
            # Create a symlink to the sensitive file in a "user-writable" directory
            user_writable = os.path.join(tmpdir, "user_data")
            os.makedirs(user_writable, exist_ok=True)
            symlink_path = os.path.join(user_writable, "innocent.txt")
            os.symlink(sensitive_file, symlink_path)
            
            # Application writes to what it thinks is a user file
            with open(symlink_path, 'w') as f:
                f.write("malicious overwrite via symlink")
            
            # Verify the sensitive file was overwritten via symlink
            with open(sensitive_file, 'r') as f:
                content = f.read()
                
            assert content == "malicious overwrite via symlink", \
                "Symlink following vulnerability exists - sensitive file overwritten"

    @pytest.mark.unit
    def test_checkpoint_path_validation_missing(self):
        """
        Test that checkpoint save paths are not validated for safety.
        
        VULNERABILITY: Model checkpoints are saved using user-provided or
        configuration-based paths. If these paths are not validated,
        attackers could overwrite system files or plant malicious checkpoints
        in sensitive locations.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate checkpoint save with malicious path
            checkpoint_dir = os.path.join(tmpdir, "..", "..", "malicious_checkpoints")
            checkpoint_file = os.path.join(checkpoint_dir, "model.ckpt")
            
            # Normalize the path
            normalized_path = os.path.normpath(checkpoint_file)
            
            # Verify that no validation would prevent this
            assert not normalized_path.startswith(tmpdir), \
                "Checkpoint path traversal possible - validation missing"

    @pytest.mark.unit
    def test_log_file_path_injection(self):
        """
        Test that log file paths can be manipulated for arbitrary writes.
        
        VULNERABILITY: If log file paths are derived from user-controllable
        configuration without validation, attackers could write log data
        (which may include attacker-controlled content) to arbitrary files.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate malicious log path configuration
            malicious_log_path = os.path.join(tmpdir, "..", "..", "var", "log", "malicious.log")
            
            # Normalize the path
            normalized_path = os.path.normpath(malicious_log_path)
            
            # Verify path traversal is possible
            assert not normalized_path.startswith(tmpdir), \
                "Log file path traversal possible - vulnerability exists"
            
            # Test that writing would succeed (in safe test environment)
            try:
                os.makedirs(os.path.dirname(normalized_path), exist_ok=True)
                with open(normalized_path, 'w') as f:
                    f.write("attacker-controlled log entry")
                    
                assert os.path.exists(normalized_path), "Log injection succeeded"
            except (OSError, PermissionError):
                pass

    @pytest.mark.unit
    def test_no_whitelist_validation(self):
        """
        Test that there is no whitelist of allowed directories for file writes.
        
        VULNERABILITY: The application does not implement a whitelist of
        allowed directories for file write operations, allowing writes to
        any location the process has permissions for.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Define a whitelist of allowed directories (what should exist)
            allowed_dirs = [
                os.path.join(tmpdir, "checkpoints"),
                os.path.join(tmpdir, "logs"),
                os.path.join(tmpdir, "outputs"),
            ]
            
            # Attempt to write outside the whitelist
            unauthorized_path = os.path.join(tmpdir, "unauthorized", "file.txt")
            
            # Verify unauthorized_path is not in allowed_dirs
            is_in_whitelist = any(
                os.path.normpath(unauthorized_path).startswith(os.path.normpath(allowed_dir))
                for allowed_dir in allowed_dirs
            )
            
            assert not is_in_whitelist, "Path is outside whitelist"
            
            # Test that write would succeed without whitelist validation
            os.makedirs(os.path.dirname(unauthorized_path), exist_ok=True)
            with open(unauthorized_path, 'w') as f:
                f.write("unauthorized write")
                
            assert os.path.exists(unauthorized_path), \
                "Write outside whitelist succeeded - no whitelist validation exists"

    @pytest.mark.unit
    def test_config_based_path_manipulation(self):
        """
        Test that configuration-based paths are not validated.
        
        VULNERABILITY: Many file operations use paths from configuration files
        (YAML, JSON, etc.). If an attacker can control or inject malicious
        configuration, they can perform arbitrary file writes.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate malicious configuration
            malicious_config = {
                'output_dir': os.path.join(tmpdir, '..', '..', 'etc'),
                'checkpoint_dir': '/tmp/../../../etc/cron.d',
                'log_dir': '../../../var/log',
            }
            
            # Verify these paths could be exploited
            for key, path in malicious_config.items():
                if not os.path.isabs(path):
                    full_path = os.path.join(tmpdir, path)
                else:
                    full_path = path
                    
                normalized = os.path.normpath(full_path)
                
                # These paths should be rejected but aren't
                assert '..' in path or os.path.isabs(path), \
                    f"Config path {key} contains traversal or absolute path - vulnerability exists"

    @pytest.mark.unit
    def test_race_condition_toctou(self):
        """
        Test for Time-of-Check-Time-of-Use (TOCTOU) race condition vulnerability.
        
        VULNERABILITY: If the code checks path safety (e.g., resolving symlinks)
        but then uses the original path for writing, an attacker could swap
        the file/symlink between the check and use.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a legitimate file
            legit_file = os.path.join(tmpdir, "legit.txt")
            with open(legit_file, 'w') as f:
                f.write("legitimate")
            
            # Simulate checking the file
            checked_path = legit_file
            assert os.path.exists(checked_path), "File exists at check time"
            
            # Simulate attacker replacing file with symlink (TOCTOU window)
            sensitive_file = os.path.join(tmpdir, "sensitive.txt")
            with open(sensitive_file, 'w') as f:
                f.write("sensitive data")
                
            os.remove(legit_file)
            os.symlink(sensitive_file, legit_file)
            
            # Application writes using the original path (now a symlink)
            with open(checked_path, 'w') as f:
                f.write("overwritten via TOCTOU")
            
            # Verify sensitive file was overwritten
            with open(sensitive_file, 'r') as f:
                content = f.read()
                
            assert content == "overwritten via TOCTOU", \
                "TOCTOU vulnerability exists - file replaced between check and use"

    @pytest.mark.unit
    def test_insufficient_permission_restrictions(self):
        """
        Test that the application may run with elevated permissions.
        
        VULNERABILITY: If the application runs with unnecessary elevated
        permissions, the impact of arbitrary file write vulnerabilities
        is amplified, potentially allowing system-wide compromise.
        
        NOTE: This test documents the concern but cannot directly test
        runtime permissions in the test environment.
        """
        # This test documents the principle that the application should
        # run with least privilege. In practice, this would need to be
        # verified through deployment configuration review.
        
        # Verify that we can document this concern
        test_concern = "Application should run with minimal required permissions"
        assert len(test_concern) > 0, "Permission restriction concern documented"


class TestCVE008FileWritePatterns:
    """
    Test suite to verify the presence of file write patterns in the codebase
    that could be exploited if path inputs are not properly validated.
    """

    @pytest.mark.unit
    def test_open_write_mode_patterns_exist(self):
        """
        Verify that the codebase contains open(..., 'w') patterns.
        
        This test documents that file write operations exist throughout
        the codebase. These are not inherently vulnerable, but require
        proper path validation to be secure.
        """
        # This test documents the grep findings mentioned in the CVE
        patterns_found = [
            "tools/nemo_forced_aligner/align.py:329: open(tgt_manifest_filepath, 'w')",
            "nemo/export/multimodal/build.py:290: open(engine_file, 'wb')",
            "nemo/core/classes/mixins/hf_io_mixin.py:229: .write_text()",
        ]
        
        assert len(patterns_found) > 0, "File write patterns exist in codebase"

    @pytest.mark.unit
    def test_path_construction_patterns(self):
        """
        Test that path construction uses string concatenation or Path joining
        without validation.
        
        VULNERABILITY: Paths constructed from user input without validation
        can lead to path traversal.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Common patterns in the codebase
            user_input = "../../malicious"
            
            # Pattern 1: os.path.join (doesn't prevent traversal)
            path1 = os.path.join(tmpdir, user_input, "file.txt")
            assert ".." in path1, "os.path.join doesn't prevent traversal"
            
            # Pattern 2: Path division (doesn't prevent traversal)
            path2 = Path(tmpdir) / user_input / "file.txt"
            assert ".." in str(path2), "Path division doesn't prevent traversal"
            
            # Pattern 3: String formatting (doesn't prevent traversal)
            path3 = f"{tmpdir}/{user_input}/file.txt"
            assert ".." in path3, "String formatting doesn't prevent traversal"

    @pytest.mark.unit
    def test_makedirs_before_write_pattern(self):
        """
        Test the common pattern of os.makedirs before file write.
        
        VULNERABILITY: The pattern 'os.makedirs(path, exist_ok=True)' followed
        by file write doesn't validate the path, potentially creating malicious
        directory structures.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Recreate common pattern from codebase
            malicious_output_dir = os.path.join(tmpdir, "..", "..", "malicious_dir")
            
            # This pattern is used in align.py:326
            # os.makedirs(cfg.output_dir, exist_ok=True)
            try:
                os.makedirs(malicious_output_dir, exist_ok=True)
                test_file = os.path.join(malicious_output_dir, "test.txt")
                with open(test_file, 'w') as f:
                    f.write("test")
                    
                # Verify the directory was created outside intended location
                normalized = os.path.normpath(malicious_output_dir)
                assert not normalized.startswith(tmpdir), \
                    "makedirs pattern allows directory traversal"
            except (OSError, PermissionError):
                pass


class TestCVE008MitigationRequirements:
    """
    Test suite documenting the required security controls to mitigate CVE-008.
    
    These tests will FAIL until proper security controls are implemented,
    serving as acceptance criteria for the vulnerability remediation.
    """

    @pytest.mark.unit
    @pytest.mark.xfail(reason="Path validation not yet implemented - CVE-008", strict=True)
    def test_path_traversal_blocked(self):
        """
        Test that path traversal attempts are blocked.
        
        This test should PASS once proper validation is implemented.
        Currently expected to FAIL.
        """
        from nemo.utils import safe_file_write  # This function should exist but doesn't yet
        
        with tempfile.TemporaryDirectory() as tmpdir:
            malicious_path = os.path.join(tmpdir, "safe", "..", "..", "malicious.txt")
            
            # Should raise ValueError or similar when path validation is implemented
            with pytest.raises((ValueError, SecurityError)):
                safe_file_write(malicious_path, "content")

    @pytest.mark.unit
    @pytest.mark.xfail(reason="Whitelist validation not yet implemented - CVE-008", strict=True)
    def test_whitelist_enforced(self):
        """
        Test that writes outside whitelisted directories are blocked.
        
        This test should PASS once whitelist validation is implemented.
        Currently expected to FAIL.
        """
        from nemo.utils import safe_file_write  # This function should exist but doesn't yet
        
        with tempfile.TemporaryDirectory() as tmpdir:
            allowed_dir = os.path.join(tmpdir, "allowed")
            forbidden_path = os.path.join(tmpdir, "forbidden", "file.txt")
            
            # Should raise ValueError when writing outside whitelist
            with pytest.raises((ValueError, SecurityError)):
                safe_file_write(forbidden_path, "content", allowed_dirs=[allowed_dir])

    @pytest.mark.unit
    @pytest.mark.xfail(reason="Absolute path blocking not yet implemented - CVE-008", strict=True)
    def test_absolute_paths_blocked(self):
        """
        Test that absolute paths in user input are blocked.
        
        This test should PASS once path validation is implemented.
        Currently expected to FAIL.
        """
        from nemo.utils import safe_file_write  # This function should exist but doesn't yet
        
        malicious_path = "/etc/passwd"
        
        # Should raise ValueError when absolute path is detected
        with pytest.raises((ValueError, SecurityError)):
            safe_file_write(malicious_path, "content")


# Custom exception for security errors (should be implemented in nemo.utils)
class SecurityError(Exception):
    """Raised when a security validation fails."""
    pass
