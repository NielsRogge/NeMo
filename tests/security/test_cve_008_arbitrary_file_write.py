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
Security tests for CVE-008: Arbitrary File Write Vulnerability

This test suite verifies the presence of potential arbitrary file write vulnerabilities
in the NeMo framework. These tests are designed to detect unsafe file write patterns
where file paths may be controlled by user input or external configuration without
proper validation.

CRITICAL SEVERITY: These vulnerabilities could allow attackers to:
- Overwrite critical system files
- Write malicious scripts to sensitive locations
- Perform privilege escalation attacks
"""

import ast
import os
import tempfile
from pathlib import Path
from typing import List, Tuple

import pytest


class FileWriteSecurityAnalyzer(ast.NodeVisitor):
    """
    AST visitor to detect potentially unsafe file write operations.
    
    This analyzer identifies:
    1. open() calls with write mode ('w', 'wb', 'w+', etc.)
    2. Path.write_text() and Path.write_bytes() calls
    3. File paths that may be controllable by external input
    """
    
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.source_lines = source_code.split('\n')
        self.unsafe_writes = []
        self.file_path = None
        
    def visit_Call(self, node: ast.Call):
        """Detect potentially unsafe file write operations."""
        
        # Check for open() with write mode
        if isinstance(node.func, ast.Name) and node.func.id == 'open':
            self._check_open_call(node)
        
        # Check for Path.write_text() or Path.write_bytes()
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in ['write_text', 'write_bytes']:
                self._check_path_write(node)
        
        self.generic_visit(node)
    
    def _check_open_call(self, node: ast.Call):
        """Check if open() call uses write mode with potentially unsafe path."""
        if len(node.args) >= 2:
            mode_arg = node.args[1]
            
            # Check if mode is a write mode
            write_modes = ['w', 'wb', 'w+', 'wb+', 'a', 'ab']
            is_write_mode = False
            
            if isinstance(mode_arg, ast.Constant):
                if mode_arg.value in write_modes:
                    is_write_mode = True
            
            if is_write_mode:
                file_path_arg = node.args[0]
                if self._is_potentially_controllable(file_path_arg):
                    self.unsafe_writes.append({
                        'type': 'open_write',
                        'line': node.lineno,
                        'code': self._get_source_line(node.lineno),
                        'reason': 'File path may be controllable by external input'
                    })
        
        # Check for mode in kwargs
        for keyword in node.keywords:
            if keyword.arg == 'mode':
                if isinstance(keyword.value, ast.Constant):
                    if any(m in str(keyword.value.value) for m in ['w', 'a']):
                        file_path_arg = node.args[0] if node.args else None
                        if file_path_arg and self._is_potentially_controllable(file_path_arg):
                            self.unsafe_writes.append({
                                'type': 'open_write',
                                'line': node.lineno,
                                'code': self._get_source_line(node.lineno),
                                'reason': 'File path may be controllable by external input'
                            })
    
    def _check_path_write(self, node: ast.Call):
        """Check if Path.write_text() or write_bytes() uses potentially unsafe path."""
        if isinstance(node.func.value, ast.Call) or isinstance(node.func.value, ast.Name):
            # Path object that could be user-controlled
            self.unsafe_writes.append({
                'type': 'path_write',
                'line': node.lineno,
                'code': self._get_source_line(node.lineno),
                'reason': 'Path object may be controllable by external input'
            })
    
    def _is_potentially_controllable(self, node: ast.AST) -> bool:
        """
        Determine if a file path could be controlled by external input.
        
        Returns True if:
        - Path is from a variable (could be from config/input)
        - Path is constructed from multiple parts
        - Path uses string formatting
        - Path involves Path operations
        """
        
        # Variables could be from external sources
        if isinstance(node, ast.Name):
            return True
        
        # Attribute access (e.g., cfg.output_dir, args.path)
        if isinstance(node, ast.Attribute):
            return True
        
        # String formatting (f-strings, .format(), %)
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ['format', 'join']:
                    return True
        
        # Path operations (Path(...) / "file")
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Div):  # Path division operator
                return True
        
        # Function calls that return paths
        if isinstance(node, ast.Call):
            return True
        
        return False
    
    def _get_source_line(self, lineno: int) -> str:
        """Get the source code line for a given line number."""
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""


def analyze_file_for_unsafe_writes(file_path: Path) -> List[dict]:
    """
    Analyze a Python file for potentially unsafe file write operations.
    
    Args:
        file_path: Path to the Python file to analyze
        
    Returns:
        List of dictionaries containing unsafe write information
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        tree = ast.parse(source_code)
        analyzer = FileWriteSecurityAnalyzer(source_code)
        analyzer.file_path = str(file_path)
        analyzer.visit(tree)
        
        return analyzer.unsafe_writes
    except (SyntaxError, UnicodeDecodeError, Exception) as e:
        # Skip files that can't be parsed
        return []


class TestCVE008ArbitraryFileWrite:
    """
    Test suite for CVE-008: Arbitrary File Write vulnerability.
    
    These tests verify that the codebase contains potentially unsafe file write
    operations that could be exploited if file paths are controllable by attackers.
    """
    
    @pytest.fixture
    def nemo_root(self):
        """Get the NeMo repository root directory."""
        return Path(__file__).parent.parent.parent
    
    @pytest.fixture
    def vulnerable_files(self):
        """
        List of files explicitly mentioned in CVE-008 as containing
        potentially unsafe file write operations.
        """
        return [
            'tools/nemo_forced_aligner/align.py',
            'nemo/export/multimodal/build.py',
            'nemo/core/classes/mixins/hf_io_mixin.py',
        ]
    
    def test_align_py_file_write_vulnerability(self, nemo_root):
        """
        Test: Verify align.py contains unsafe file write operation.
        
        CVE-008 Reference: Line 329 in align.py
        Code: f_manifest_out = open(tgt_manifest_filepath, 'w')
        
        Vulnerability: The tgt_manifest_filepath is constructed from cfg.output_dir
        which could be controlled by user configuration, allowing arbitrary file writes.
        """
        file_path = nemo_root / 'tools' / 'nemo_forced_aligner' / 'align.py'
        
        assert file_path.exists(), f"File not found: {file_path}"
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check for the vulnerable pattern
        assert "open(tgt_manifest_filepath, 'w')" in content, \
            "Expected vulnerable file write pattern not found in align.py"
        
        # Verify path is constructed from configuration
        assert 'cfg.output_dir' in content, \
            "Configuration-based path construction not found"
        
        # Analyze for unsafe writes
        unsafe_writes = analyze_file_for_unsafe_writes(file_path)
        
        assert len(unsafe_writes) > 0, \
            "No potentially unsafe file write operations detected in align.py"
    
    def test_build_py_file_write_vulnerability(self, nemo_root):
        """
        Test: Verify build.py contains unsafe file write operation.
        
        CVE-008 Reference: Line 290 in build.py
        Code: with open(engine_file, 'wb') as f:
        
        Vulnerability: The engine_file parameter could be controlled by external
        input, allowing an attacker to write binary data to arbitrary locations.
        """
        file_path = nemo_root / 'nemo' / 'export' / 'multimodal' / 'build.py'
        
        assert file_path.exists(), f"File not found: {file_path}"
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check for the vulnerable pattern
        assert "open(engine_file, 'wb')" in content or "open(engine_file,'wb')" in content, \
            "Expected vulnerable file write pattern not found in build.py"
        
        # Analyze for unsafe writes
        unsafe_writes = analyze_file_for_unsafe_writes(file_path)
        
        assert len(unsafe_writes) > 0, \
            "No potentially unsafe file write operations detected in build.py"
    
    def test_hf_io_mixin_write_text_vulnerability(self, nemo_root):
        """
        Test: Verify hf_io_mixin.py contains unsafe write_text operation.
        
        CVE-008 Reference: Line 229 in hf_io_mixin.py
        Code: model_card_filepath.write_text(str(model_card), encoding='utf-8', errors='ignore')
        
        Vulnerability: The model_card_filepath is constructed from saved_path,
        which could be manipulated to write to unintended locations.
        """
        file_path = nemo_root / 'nemo' / 'core' / 'classes' / 'mixins' / 'hf_io_mixin.py'
        
        assert file_path.exists(), f"File not found: {file_path}"
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check for the vulnerable pattern
        assert '.write_text(' in content, \
            "Expected vulnerable write_text pattern not found in hf_io_mixin.py"
        
        assert 'model_card_filepath' in content, \
            "model_card_filepath variable not found"
        
        # Analyze for unsafe writes
        unsafe_writes = analyze_file_for_unsafe_writes(file_path)
        
        assert len(unsafe_writes) > 0, \
            "No potentially unsafe file write operations detected in hf_io_mixin.py"
    
    def test_widespread_file_write_usage(self, nemo_root):
        """
        Test: Verify widespread use of file write operations across codebase.
        
        This test demonstrates that file write operations are used extensively
        throughout the codebase, increasing the attack surface for arbitrary
        file write vulnerabilities.
        """
        nemo_dir = nemo_root / 'nemo'
        
        python_files = list(nemo_dir.rglob('*.py'))
        
        files_with_unsafe_writes = []
        total_unsafe_writes = 0
        
        for py_file in python_files[:100]:  # Sample first 100 files for test performance
            unsafe_writes = analyze_file_for_unsafe_writes(py_file)
            if unsafe_writes:
                files_with_unsafe_writes.append(py_file)
                total_unsafe_writes += len(unsafe_writes)
        
        # Assert that multiple files contain potentially unsafe write operations
        assert len(files_with_unsafe_writes) >= 10, \
            f"Expected to find unsafe writes in multiple files, found only {len(files_with_unsafe_writes)}"
        
        assert total_unsafe_writes >= 10, \
            f"Expected significant number of unsafe write operations, found only {total_unsafe_writes}"
    
    def test_directory_traversal_not_prevented(self, nemo_root):
        """
        Test: Verify that directory traversal attacks are not prevented.
        
        This test checks if the codebase contains path validation to prevent
        directory traversal attacks (e.g., using '../../../etc/passwd').
        """
        # Check common files for path validation patterns
        validation_patterns = [
            'os.path.abspath',
            'Path.resolve',
            '.resolve()',
            'realpath',
            'normpath',
        ]
        
        nemo_dir = nemo_root / 'nemo'
        python_files = list(nemo_dir.rglob('*.py'))
        
        files_with_validation = 0
        files_with_writes = 0
        
        for py_file in python_files[:100]:  # Sample for performance
            with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            has_write = 'open(' in content and ("'w'" in content or '"w"' in content)
            has_validation = any(pattern in content for pattern in validation_patterns)
            
            if has_write:
                files_with_writes += 1
                if has_validation:
                    files_with_validation += 1
        
        # Calculate validation ratio
        if files_with_writes > 0:
            validation_ratio = files_with_validation / files_with_writes
            
            # Assert that path validation is not consistently applied
            assert validation_ratio < 0.5, \
                f"Path validation is applied in {validation_ratio*100:.1f}% of files with writes. " \
                "This suggests inconsistent security practices."
    
    def test_config_controlled_paths_unsafe(self, nemo_root):
        """
        Test: Verify that configuration-controlled paths are used unsafely.
        
        Many file write operations use paths from configuration objects (cfg, args, etc.)
        without validation, allowing potential manipulation through config files.
        """
        config_patterns = [
            'cfg.',
            'args.',
            'config.',
            'conf.',
        ]
        
        vulnerable_files = []
        
        # Check the explicitly mentioned vulnerable files
        test_files = [
            nemo_root / 'tools' / 'nemo_forced_aligner' / 'align.py',
            nemo_root / 'nemo' / 'export' / 'multimodal' / 'build.py',
        ]
        
        for file_path in test_files:
            if not file_path.exists():
                continue
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if file uses config-based paths with file writes
            has_config_path = any(pattern in content for pattern in config_patterns)
            has_file_write = ("open(" in content and "'w" in content) or '.write_text(' in content
            
            if has_config_path and has_file_write:
                vulnerable_files.append(file_path.name)
        
        assert len(vulnerable_files) > 0, \
            "No files found that use configuration-controlled paths with file writes"
    
    def test_no_whitelist_directory_validation(self, nemo_root):
        """
        Test: Verify absence of whitelist-based directory validation.
        
        The solution design recommends using a whitelist of allowed directories.
        This test verifies that such validation is not currently implemented.
        """
        whitelist_patterns = [
            'ALLOWED_DIRECTORIES',
            'SAFE_PATHS',
            'WHITELIST',
            'allowed_dirs',
            'safe_directories',
        ]
        
        nemo_dir = nemo_root / 'nemo'
        
        # Search for whitelist implementations
        whitelist_found = False
        
        for py_file in nemo_dir.rglob('*.py'):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if any(pattern in content for pattern in whitelist_patterns):
                    whitelist_found = True
                    break
            except:
                continue
        
        # Assert that whitelist validation is not implemented
        assert not whitelist_found, \
            "Whitelist-based directory validation found - this vulnerability may be mitigated"
    
    def test_path_sanitization_missing(self, nemo_root):
        """
        Test: Verify that path sanitization is not consistently applied.
        
        Checks for common path sanitization functions before file write operations.
        """
        sanitization_functions = [
            'sanitize_path',
            'validate_path',
            'check_path',
            'safe_path',
            'secure_path',
        ]
        
        # Check vulnerable files for sanitization
        vulnerable_files = [
            nemo_root / 'tools' / 'nemo_forced_aligner' / 'align.py',
            nemo_root / 'nemo' / 'export' / 'multimodal' / 'build.py',
            nemo_root / 'nemo' / 'core' / 'classes' / 'mixins' / 'hf_io_mixin.py',
        ]
        
        files_without_sanitization = []
        
        for file_path in vulnerable_files:
            if not file_path.exists():
                continue
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            has_sanitization = any(func in content for func in sanitization_functions)
            
            if not has_sanitization:
                files_without_sanitization.append(file_path.name)
        
        # Assert that sanitization is missing
        assert len(files_without_sanitization) >= 2, \
            f"Expected multiple files without sanitization, found: {files_without_sanitization}"


class TestCVE008ExploitScenarios:
    """
    Test suite demonstrating potential exploit scenarios for CVE-008.
    
    These tests show how an attacker could exploit the arbitrary file write
    vulnerability in realistic attack scenarios.
    """
    
    def test_directory_traversal_attack_scenario(self):
        """
        Test: Demonstrate directory traversal attack scenario.
        
        An attacker could use '../' sequences in configuration to write files
        outside the intended directory.
        """
        # Simulate malicious configuration
        malicious_paths = [
            '../../../etc/cron.d/malicious',
            '../../../tmp/evil.sh',
            '../../.ssh/authorized_keys',
            '../../../../../etc/passwd',
        ]
        
        for malicious_path in malicious_paths:
            # Verify that such paths would not be caught by simple checks
            assert '..' in malicious_path, \
                f"Directory traversal pattern should be present in: {malicious_path}"
            
            # Show that Path normalization would resolve to unintended location
            resolved = Path(malicious_path)
            assert str(resolved).startswith('..'), \
                "Path traversal would escape intended directory"
    
    def test_absolute_path_attack_scenario(self):
        """
        Test: Demonstrate absolute path attack scenario.
        
        An attacker could specify absolute paths in configuration to write
        to arbitrary system locations.
        """
        malicious_absolute_paths = [
            '/etc/cron.d/backdoor',
            '/var/www/html/shell.php',
            '/root/.ssh/authorized_keys',
            '/etc/ld.so.preload',
        ]
        
        for malicious_path in malicious_absolute_paths:
            path = Path(malicious_path)
            assert path.is_absolute(), \
                f"Malicious path should be absolute: {malicious_path}"
    
    def test_symlink_attack_scenario(self, tmp_path):
        """
        Test: Demonstrate symlink attack scenario.
        
        An attacker could create a symlink in an allowed directory that points
        to a sensitive system file, then trigger a write to that symlink.
        """
        # Create a temporary "allowed" directory
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        
        # Create a file that simulates a sensitive system file
        sensitive_file = tmp_path / "sensitive.txt"
        sensitive_file.write_text("SENSITIVE DATA")
        
        # Create a symlink in the allowed directory
        symlink_path = allowed_dir / "output.txt"
        symlink_path.symlink_to(sensitive_file)
        
        # Demonstrate that writing to symlink would overwrite sensitive file
        assert symlink_path.exists(), "Symlink should exist"
        assert symlink_path.is_symlink(), "Path should be a symlink"
        
        # If code writes to symlink_path without checking, it would overwrite sensitive_file
        symlink_path.write_text("OVERWRITTEN")
        
        # Verify sensitive file was overwritten
        assert sensitive_file.read_text() == "OVERWRITTEN", \
            "Symlink attack successfully overwrites sensitive file"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
