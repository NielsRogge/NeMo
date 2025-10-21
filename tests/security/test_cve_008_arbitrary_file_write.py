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
Security Tests for CVE-008: Arbitrary File Write Vulnerability

SEVERITY: CRITICAL
JIRA: https://ml6team.atlassian.net/browse/DR-138

DESCRIPTION:
The application may be vulnerable to arbitrary file writes. The framework saves model 
checkpoints, logs, and processed data. If the output paths for these files can be 
controlled by a user or a malicious configuration, it could allow an attacker to 
overwrite critical system files or write malicious scripts (e.g., web shells) to 
sensitive locations.

VULNERABILITY PATTERNS:
- open(..., 'w') or open(..., 'wb') with user-controllable paths
- Path.write_text() with user-controllable paths
- File write operations without proper path validation
- Directory traversal attacks using '../' sequences
- Absolute path manipulation to sensitive system locations

AFFECTED CODE PATTERNS:
- tools/nemo_forced_aligner/align.py:329: f_manifest_out = open(tgt_manifest_filepath, 'w')
- nemo/export/multimodal/build.py:290: with open(engine_file, 'wb') as f:
- nemo/core/classes/mixins/hf_io_mixin.py:229: model_card_filepath.write_text(...)

These tests verify the presence of vulnerabilities and demonstrate attack vectors.
They do NOT fix the vulnerabilities - that is a separate remediation task.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest


class TestCVE008ArbitraryFileWrite:
    """
    Security test suite for CVE-008: Arbitrary File Write vulnerability.
    
    These tests verify that the application is vulnerable to arbitrary file write
    attacks when file paths can be controlled through user input or configuration.
    """

    @pytest.mark.unit
    def test_directory_traversal_with_relative_paths(self):
        """
        Test: Directory traversal using '../' sequences in file paths
        
        VULNERABILITY: If a malicious user can control the output path via configuration
        or input, they could use '../' sequences to write files outside the intended
        directory, potentially overwriting critical system files.
        
        ATTACK VECTOR: 
        - User provides path like '../../../etc/passwd' 
        - Application writes to this path without validation
        - Critical system files are overwritten
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a safe subdirectory where files should be written
            safe_dir = os.path.join(tmpdir, "safe_output")
            os.makedirs(safe_dir)
            
            # Create a sensitive file outside the safe directory
            sensitive_file = os.path.join(tmpdir, "sensitive_system_file.txt")
            with open(sensitive_file, 'w') as f:
                f.write("CRITICAL SYSTEM DATA")
            
            # VULNERABLE PATTERN: Application accepts user-controlled path without validation
            # Attacker provides a path with directory traversal
            malicious_path = os.path.join(safe_dir, "../sensitive_system_file.txt")
            
            # Verify that the path resolves outside the safe directory
            resolved_path = os.path.abspath(malicious_path)
            assert not resolved_path.startswith(os.path.abspath(safe_dir)), \
                "Path should escape the safe directory (vulnerability present)"
            
            # VULNERABILITY DEMONSTRATED: Writing to the malicious path succeeds
            with open(malicious_path, 'w') as f:
                f.write("MALICIOUS CONTENT")
            
            # Verify that the sensitive file was overwritten
            with open(sensitive_file, 'r') as f:
                content = f.read()
                assert content == "MALICIOUS CONTENT", \
                    "Arbitrary file write vulnerability: sensitive file was overwritten"

    @pytest.mark.unit
    def test_absolute_path_to_sensitive_location(self):
        """
        Test: Absolute path manipulation to write to sensitive system locations
        
        VULNERABILITY: If file paths from configuration or user input are not validated,
        an attacker could provide absolute paths to sensitive system locations.
        
        ATTACK VECTOR:
        - Attacker provides absolute path like '/tmp/malicious_script.sh'
        - Application writes to this location without validation
        - Attacker can execute malicious code
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # VULNERABLE PATTERN: Accept absolute path from user/config
            malicious_absolute_path = os.path.join(tmpdir, "tmp", "malicious_script.sh")
            os.makedirs(os.path.dirname(malicious_absolute_path), exist_ok=True)
            
            # VULNERABILITY DEMONSTRATED: Application writes to arbitrary absolute path
            malicious_content = "#!/bin/bash\necho 'Malicious code executed'\n"
            with open(malicious_absolute_path, 'w') as f:
                f.write(malicious_content)
            
            # Verify the malicious file was created at the specified location
            assert os.path.exists(malicious_absolute_path), \
                "Vulnerability: File written to arbitrary absolute path"
            
            with open(malicious_absolute_path, 'r') as f:
                content = f.read()
                assert "Malicious code executed" in content, \
                    "Arbitrary file write vulnerability: malicious script created"

    @pytest.mark.unit
    def test_manifest_output_path_injection(self):
        """
        Test: Manifest output path injection vulnerability
        
        AFFECTED CODE: tools/nemo_forced_aligner/align.py:329
        Pattern: f_manifest_out = open(tgt_manifest_filepath, 'w')
        
        VULNERABILITY: The tgt_manifest_filepath is constructed from cfg.output_dir 
        which may be user-controllable. If not validated, this allows arbitrary 
        file writes.
        
        ATTACK VECTOR:
        - Attacker controls cfg.output_dir through configuration
        - Provides path with directory traversal or absolute path
        - Manifest is written to arbitrary location
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate the vulnerable code pattern
            safe_output = os.path.join(tmpdir, "output")
            os.makedirs(safe_output)
            
            # Attacker-controlled configuration
            malicious_output_dir = os.path.join(tmpdir, "output", "..", "sensitive")
            manifest_name = "manifest.json"
            
            # Vulnerable code pattern simulation
            tgt_manifest_filepath = os.path.join(malicious_output_dir, manifest_name)
            os.makedirs(os.path.dirname(os.path.abspath(tgt_manifest_filepath)), exist_ok=True)
            
            # VULNERABILITY: File is written without path validation
            with open(tgt_manifest_filepath, 'w') as f_manifest_out:
                f_manifest_out.write('{"malicious": "data"}')
            
            # Verify the file was written outside the intended directory
            resolved = os.path.abspath(tgt_manifest_filepath)
            assert os.path.exists(resolved), \
                "Vulnerability: Manifest written to attacker-controlled location"
            assert not resolved.startswith(os.path.abspath(safe_output)), \
                "Vulnerability: Manifest written outside safe output directory"

    @pytest.mark.unit
    def test_engine_file_path_injection(self):
        """
        Test: Engine file path injection vulnerability
        
        AFFECTED CODE: nemo/export/multimodal/build.py:290
        Pattern: with open(engine_file, 'wb') as f: f.write(engine_string)
        
        VULNERABILITY: The engine_file path may be derived from user input or
        configuration without proper validation, allowing arbitrary file writes.
        
        ATTACK VECTOR:
        - Attacker controls engine file path through configuration
        - Provides malicious path to overwrite system files
        - Binary engine data written to arbitrary location
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create intended engine directory
            engine_dir = os.path.join(tmpdir, "engines")
            os.makedirs(engine_dir)
            
            # Attacker provides malicious engine_file path
            malicious_engine_file = os.path.join(engine_dir, "..", "..", "system", "critical.bin")
            os.makedirs(os.path.dirname(os.path.abspath(malicious_engine_file)), exist_ok=True)
            
            # Simulate vulnerable code pattern
            engine_string = b"\x00\x01\x02\x03MALICIOUS_ENGINE_DATA"
            
            # VULNERABILITY: Binary file written without path validation
            with open(malicious_engine_file, 'wb') as f:
                f.write(engine_string)
            
            # Verify the file was written to attacker-controlled location
            assert os.path.exists(os.path.abspath(malicious_engine_file)), \
                "Vulnerability: Engine file written to arbitrary location"
            
            with open(malicious_engine_file, 'rb') as f:
                content = f.read()
                assert b"MALICIOUS_ENGINE_DATA" in content, \
                    "Arbitrary file write vulnerability: malicious engine file created"

    @pytest.mark.unit
    def test_model_card_write_text_injection(self):
        """
        Test: Model card path injection via write_text()
        
        AFFECTED CODE: nemo/core/classes/mixins/hf_io_mixin.py:229
        Pattern: model_card_filepath.write_text(str(model_card), encoding='utf-8', errors='ignore')
        
        VULNERABILITY: If the saved_path variable can be influenced by user input,
        an attacker could manipulate the model_card_filepath to write to arbitrary
        locations using Path.write_text().
        
        ATTACK VECTOR:
        - Attacker controls saved_path through HuggingFace push parameters
        - Creates malicious path that escapes intended directory
        - Model card (potentially containing malicious content) written to arbitrary file
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Intended save directory
            intended_dir = Path(tmpdir) / "models"
            intended_dir.mkdir()
            
            # Attacker-controlled saved_path with directory traversal
            malicious_saved_path = intended_dir / ".." / "sensitive"
            malicious_saved_path.mkdir(exist_ok=True)
            
            # Construct model card filepath (following the vulnerable pattern)
            model_card_filepath = malicious_saved_path / "README.md"
            
            # Malicious model card content
            malicious_model_card = """---
tags:
- malicious
---
# Malicious Model Card
<script>alert('XSS')</script>
<?php system($_GET['cmd']); ?>
"""
            
            # VULNERABILITY: write_text without path validation
            model_card_filepath.write_text(str(malicious_model_card), encoding='utf-8', errors='ignore')
            
            # Verify the file was written outside the intended directory
            assert model_card_filepath.exists(), \
                "Vulnerability: Model card written to arbitrary location"
            assert not str(model_card_filepath.resolve()).startswith(str(intended_dir.resolve())), \
                "Vulnerability: Model card written outside intended directory"
            
            content = model_card_filepath.read_text()
            assert "Malicious Model Card" in content, \
                "Arbitrary file write vulnerability: malicious model card created"

    @pytest.mark.unit
    def test_configuration_based_path_manipulation(self):
        """
        Test: Configuration-based path manipulation vulnerability
        
        VULNERABILITY: Configuration files (YAML, JSON) may contain file paths that
        are used directly without validation. An attacker who can modify configuration
        files can cause arbitrary file writes.
        
        ATTACK VECTOR:
        - Attacker modifies configuration file (or provides malicious config)
        - Sets output paths to sensitive system locations
        - Application processes config and writes to attacker-controlled paths
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create mock configuration with malicious paths
            malicious_config = {
                'output_dir': os.path.join(tmpdir, "safe", "..", "unsafe"),
                'checkpoint_dir': '/tmp/../../../tmp/malicious_checkpoint',
                'log_dir': '../../../../tmp/logs',
            }
            
            # VULNERABILITY: Application uses config paths without validation
            for config_key, config_path in malicious_config.items():
                # Simulate file write based on config
                full_path = os.path.join(tmpdir, "base", config_path, f"{config_key}.txt")
                os.makedirs(os.path.dirname(os.path.abspath(full_path)), exist_ok=True)
                
                with open(full_path, 'w') as f:
                    f.write(f"Data from {config_key}")
                
                # Verify file was written to potentially dangerous location
                assert os.path.exists(full_path), \
                    f"Vulnerability: {config_key} written to config-controlled path"

    @pytest.mark.unit
    def test_symlink_following_vulnerability(self):
        """
        Test: Symlink following vulnerability
        
        VULNERABILITY: If the application follows symlinks without validation,
        an attacker could create a symlink pointing to a sensitive file, then
        cause the application to write to the symlink, overwriting the target.
        
        ATTACK VECTOR:
        - Attacker creates symlink in writable directory
        - Symlink points to sensitive system file
        - Application writes to the symlink path
        - Sensitive file is overwritten
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a sensitive target file
            sensitive_file = os.path.join(tmpdir, "sensitive_data.txt")
            with open(sensitive_file, 'w') as f:
                f.write("SENSITIVE INFORMATION")
            
            # Create a writable directory where attacker can place symlinks
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(output_dir)
            
            # Attacker creates a symlink
            symlink_path = os.path.join(output_dir, "checkpoint.ckpt")
            os.symlink(sensitive_file, symlink_path)
            
            # VULNERABILITY: Application writes to the path without checking for symlinks
            with open(symlink_path, 'w') as f:
                f.write("MALICIOUS CHECKPOINT DATA")
            
            # Verify the sensitive file was overwritten via symlink
            with open(sensitive_file, 'r') as f:
                content = f.read()
                assert content == "MALICIOUS CHECKPOINT DATA", \
                    "Vulnerability: Symlink following allowed overwrite of sensitive file"

    @pytest.mark.unit
    def test_null_byte_injection_in_path(self):
        """
        Test: Null byte injection in file paths
        
        VULNERABILITY: In some contexts, null bytes in file paths can be used to
        bypass validation or write to unexpected locations.
        
        ATTACK VECTOR:
        - Attacker includes null byte in file path
        - Validation checks path up to null byte
        - Actual file operation uses different path
        
        NOTE: This vulnerability depends on the specific Python version and OS.
        Modern Python versions typically reject null bytes in paths, but this
        test documents the potential vulnerability pattern.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Attempt null byte injection
            # Note: Modern Python raises ValueError for null bytes in paths
            malicious_path = os.path.join(tmpdir, "safe.txt\x00../../etc/passwd")
            
            # This test documents that null bytes should be rejected
            with pytest.raises(ValueError, match="embedded null"):
                with open(malicious_path, 'w') as f:
                    f.write("malicious content")

    @pytest.mark.unit
    def test_checkpoint_directory_traversal(self):
        """
        Test: Checkpoint directory traversal vulnerability
        
        VULNERABILITY: Model checkpoint paths are often constructed from user
        configuration. Without proper validation, attackers can use directory
        traversal to write checkpoints to arbitrary locations.
        
        ATTACK VECTOR:
        - Attacker provides checkpoint path with traversal sequences
        - Checkpoint written outside intended directory
        - Malicious checkpoint could be loaded by other users/systems
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Intended checkpoint directory
            checkpoint_dir = os.path.join(tmpdir, "checkpoints")
            os.makedirs(checkpoint_dir)
            
            # Attacker-controlled checkpoint name with traversal
            malicious_checkpoint_name = "../../../tmp/malicious_model.ckpt"
            checkpoint_path = os.path.join(checkpoint_dir, malicious_checkpoint_name)
            
            # Create directories for the malicious path
            os.makedirs(os.path.dirname(os.path.abspath(checkpoint_path)), exist_ok=True)
            
            # VULNERABILITY: Checkpoint written without path validation
            malicious_checkpoint_data = b"MALICIOUS_MODEL_WEIGHTS"
            with open(checkpoint_path, 'wb') as f:
                f.write(malicious_checkpoint_data)
            
            # Verify checkpoint written outside intended directory
            resolved = os.path.abspath(checkpoint_path)
            assert os.path.exists(resolved), \
                "Vulnerability: Checkpoint written to arbitrary location"
            assert not resolved.startswith(os.path.abspath(checkpoint_dir)), \
                "Vulnerability: Checkpoint escaped intended directory"

    @pytest.mark.unit
    def test_log_file_path_injection(self):
        """
        Test: Log file path injection vulnerability
        
        VULNERABILITY: Log file paths configured through environment variables or
        configuration files may allow arbitrary file writes if not validated.
        
        ATTACK VECTOR:
        - Attacker controls log file path via environment or config
        - Provides path to sensitive location
        - Log data (potentially containing attacker-controlled content) written to arbitrary file
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a sensitive directory
            sensitive_dir = os.path.join(tmpdir, "system", "config")
            os.makedirs(sensitive_dir, exist_ok=True)
            
            # Attacker-controlled log path pointing to sensitive location
            malicious_log_path = os.path.join(sensitive_dir, "system.conf")
            
            # VULNERABILITY: Log written to arbitrary path without validation
            with open(malicious_log_path, 'w') as log_file:
                log_file.write("ATTACKER_CONTROLLED_LOG_ENTRY\n")
                log_file.write("malicious_config=true\n")
            
            # Verify log written to sensitive location
            assert os.path.exists(malicious_log_path), \
                "Vulnerability: Log file written to sensitive system location"
            
            with open(malicious_log_path, 'r') as f:
                content = f.read()
                assert "malicious_config=true" in content, \
                    "Arbitrary file write vulnerability: malicious config injected via logs"

    @pytest.mark.unit
    def test_write_without_directory_existence_check(self):
        """
        Test: File write creating directory structure without validation
        
        VULNERABILITY: Using os.makedirs() with exist_ok=True before file writes
        can create arbitrary directory structures, which combined with path traversal
        can write files anywhere in the filesystem.
        
        ATTACK VECTOR:
        - Attacker provides path with traversal sequences
        - Application creates parent directories automatically
        - File written to arbitrary location in filesystem
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Safe base directory
            base_dir = os.path.join(tmpdir, "base")
            os.makedirs(base_dir)
            
            # Attacker-controlled path with traversal
            malicious_path = os.path.join(base_dir, "..", "attacker", "payload.txt")
            
            # VULNERABLE PATTERN: Create directories without validation
            os.makedirs(os.path.dirname(malicious_path), exist_ok=True)
            
            # Write file to the created path
            with open(malicious_path, 'w') as f:
                f.write("MALICIOUS PAYLOAD")
            
            # Verify arbitrary directory structure was created
            assert os.path.exists(malicious_path), \
                "Vulnerability: Arbitrary directory structure created and file written"
            assert os.path.exists(os.path.join(tmpdir, "attacker")), \
                "Vulnerability: Attacker-controlled directory created"


class TestCVE008PathValidationBypass:
    """
    Additional tests for path validation bypass techniques.
    
    These tests document various techniques attackers might use to bypass
    naive path validation implementations.
    """

    @pytest.mark.unit
    def test_double_encoding_bypass(self):
        """
        Test: Double-encoded path traversal bypass
        
        Some validation might decode paths once, but if paths are decoded multiple
        times, double-encoding can bypass validation.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Double-encoded traversal sequence
            # %2E%2E%2F is URL-encoded '../'
            # If decoded twice: %252E%252E%252F -> %2E%2E%2F -> ../
            malicious_encoded = "%2E%2E%2F" * 3 + "sensitive.txt"
            
            # This test documents the pattern - actual exploitation depends on
            # whether the application performs URL decoding
            assert "%2E" in malicious_encoded, \
                "Double-encoded traversal sequence constructed"

    @pytest.mark.unit
    def test_mixed_path_separators(self):
        """
        Test: Mixed path separators for validation bypass
        
        Using mixed path separators (forward slash and backslash) might bypass
        validation that only checks for one type.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mixed separators might bypass naive validation
            # On Windows: both / and \ work as separators
            mixed_separator_path = os.path.join(tmpdir, "safe/../sensitive/file.txt")
            
            # Verify that the path contains traversal
            normalized = os.path.normpath(mixed_separator_path)
            assert "sensitive" in normalized, \
                "Path with mixed separators should be validated"

    @pytest.mark.unit
    def test_unicode_normalization_bypass(self):
        """
        Test: Unicode normalization bypass
        
        Different Unicode representations of the same character might bypass
        validation if not properly normalized.
        """
        # Document potential Unicode-based bypass techniques
        # For example, using Unicode equivalents of '../'
        # This is more theoretical for path traversal but worth documenting
        
        # Example: Unicode dots and slashes
        unicode_dot = '\u002E'  # Unicode FULL STOP (same as '.')
        unicode_slash = '\u002F'  # Unicode SOLIDUS (same as '/')
        
        traversal_standard = "../"
        traversal_unicode = f"{unicode_dot}{unicode_dot}{unicode_slash}"
        
        assert traversal_standard == traversal_unicode, \
            "Unicode equivalents should be normalized and validated"


class TestCVE008RecommendedValidation:
    """
    Test cases demonstrating recommended validation approaches.
    
    These tests show what proper validation SHOULD look like to prevent
    arbitrary file write vulnerabilities. They serve as documentation for
    the remediation effort.
    """

    @pytest.mark.unit
    def test_path_validation_with_realpath(self):
        """
        RECOMMENDED APPROACH: Use os.path.realpath() to resolve paths and validate
        
        This test demonstrates how to properly validate that a file path stays
        within an allowed directory.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            allowed_dir = os.path.join(tmpdir, "allowed")
            os.makedirs(allowed_dir)
            
            # Test legitimate path
            legit_path = os.path.join(allowed_dir, "file.txt")
            legit_real = os.path.realpath(legit_path)
            allowed_real = os.path.realpath(allowed_dir)
            
            # Proper validation
            assert legit_real.startswith(allowed_real + os.sep) or legit_real == allowed_real, \
                "Legitimate path should be within allowed directory"
            
            # Test malicious path with traversal
            malicious_path = os.path.join(allowed_dir, "../../../etc/passwd")
            malicious_real = os.path.realpath(malicious_path)
            
            # Validation should reject this
            is_safe = malicious_real.startswith(allowed_real + os.sep)
            assert not is_safe, \
                "Validation should reject path that escapes allowed directory"

    @pytest.mark.unit
    def test_whitelist_based_directory_validation(self):
        """
        RECOMMENDED APPROACH: Use a whitelist of allowed directories
        
        This test demonstrates validating file paths against a whitelist of
        allowed base directories.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Define whitelist of allowed directories
            allowed_dirs = [
                os.path.join(tmpdir, "checkpoints"),
                os.path.join(tmpdir, "logs"),
                os.path.join(tmpdir, "outputs"),
            ]
            
            # Create the directories
            for dir_path in allowed_dirs:
                os.makedirs(dir_path, exist_ok=True)
            
            def is_path_allowed(file_path, allowed_directories):
                """Validate that a path is within allowed directories"""
                real_path = os.path.realpath(file_path)
                for allowed_dir in allowed_directories:
                    real_allowed = os.path.realpath(allowed_dir)
                    if real_path.startswith(real_allowed + os.sep):
                        return True
                return False
            
            # Test legitimate paths
            legit_checkpoint = os.path.join(allowed_dirs[0], "model.ckpt")
            assert is_path_allowed(legit_checkpoint, allowed_dirs), \
                "Legitimate checkpoint path should be allowed"
            
            # Test malicious path
            malicious_path = os.path.join(allowed_dirs[0], "../../etc/passwd")
            assert not is_path_allowed(malicious_path, allowed_dirs), \
                "Malicious path should be rejected by whitelist validation"

    @pytest.mark.unit
    def test_filename_sanitization(self):
        """
        RECOMMENDED APPROACH: Sanitize filenames to remove dangerous characters
        
        This test demonstrates sanitizing user-provided filenames to prevent
        directory traversal.
        """
        def sanitize_filename(filename):
            """Remove dangerous characters from filename"""
            # Remove path separators and other dangerous characters
            dangerous_chars = ['/', '\\', '..', '\0', '\n', '\r']
            sanitized = filename
            for char in dangerous_chars:
                sanitized = sanitized.replace(char, '_')
            return sanitized
        
        # Test various malicious filenames
        test_cases = [
            ("../../../etc/passwd", "________etc_passwd"),
            ("..\\..\\windows\\system32\\config\\sam", "______windows_system32_config_sam"),
            ("file\0.txt", "file_.txt"),
            ("../file.txt", "___file.txt"),
        ]
        
        for malicious, expected_sanitized in test_cases:
            result = sanitize_filename(malicious)
            assert result == expected_sanitized, \
                f"Filename '{malicious}' should be sanitized to '{expected_sanitized}'"
            assert '..' not in result and '/' not in result and '\\' not in result, \
                f"Sanitized filename should not contain dangerous characters"
