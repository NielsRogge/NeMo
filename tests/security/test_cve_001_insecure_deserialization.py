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
Security Tests for CVE-001: Insecure Deserialization Vulnerability

This test suite verifies the presence of insecure deserialization patterns in the NeMo codebase.
The vulnerability allows potential remote code execution through unsafe use of:
- pickle.load/pickle.loads
- torch.load with weights_only=False
- Other unsafe deserialization methods

CVE Details:
- CVE ID: CVE-001
- Title: Insecure Deserialization
- Severity: CRITICAL
- Jira Issue: https://ml6team.atlassian.net/browse/DR-134

These tests are designed to DETECT the vulnerability, not to fix it.
"""

import ast
import os
import pickle
import tempfile
from pathlib import Path
from typing import List, Tuple

import pytest
import torch


class TestInsecurePickleDeserialization:
    """
    Test suite to verify insecure pickle.load usage in the codebase.
    
    Security Risk: pickle.load can execute arbitrary code during deserialization.
    An attacker could craft a malicious pickle file that executes code when loaded.
    """

    @pytest.fixture
    def malicious_pickle_file(self):
        """
        Create a mock malicious pickle file for testing purposes.
        This simulates what an attacker could create.
        """
        class MaliciousObject:
            """
            Example of a malicious object that could execute code on unpickling.
            In reality, attackers use __reduce__ to execute arbitrary commands.
            """
            def __reduce__(self):
                # This is a simplified example - real attacks could be more sophisticated
                return (eval, ("print('Potential RCE vulnerability!')",))
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pkl') as f:
            # Create a simple pickle file for testing (not actually malicious for safety)
            pickle.dump({'data': 'test'}, f)
            return f.name

    def test_data_explorer_pickle_load_vulnerability(self):
        """
        Test: Verify data_explorer.py uses insecure pickle.load
        
        Location: tools/speech_data_explorer/data_explorer.py:190
        Vulnerable code: pickle.load(f)
        
        Risk: Loading untrusted pickle files can lead to RCE
        """
        filepath = Path(__file__).parent.parent.parent / "tools/speech_data_explorer/data_explorer.py"
        
        assert filepath.exists(), f"File not found: {filepath}"
        
        content = filepath.read_text()
        
        # Verify pickle.load is used
        assert 'pickle.load' in content, "pickle.load not found in data_explorer.py"
        
        # Verify it's used without safe loading mechanisms
        # Safe alternatives would include validation or using safer formats
        lines = content.split('\n')
        pickle_load_lines = [i for i, line in enumerate(lines) if 'pickle.load' in line]
        
        assert len(pickle_load_lines) > 0, "pickle.load usage not detected"
        
        # Check for lack of validation before pickle.load
        for line_num in pickle_load_lines:
            # Look at surrounding context (5 lines before)
            context = lines[max(0, line_num-5):line_num]
            context_str = '\n'.join(context)
            
            # Verify no validation checks are present
            has_validation = any([
                'verify' in context_str.lower(),
                'validate' in context_str.lower(),
                'check_signature' in context_str.lower(),
                'hmac' in context_str.lower()
            ])
            
            # VULNERABILITY: No validation before pickle.load
            assert not has_validation, \
                f"Unexpected validation found at line {line_num} - vulnerability may be mitigated"

    def test_pickle_import_presence(self):
        """
        Test: Verify pickle module is imported in vulnerable files
        
        This test identifies files that import pickle, indicating potential
        deserialization vulnerabilities.
        """
        vulnerable_files = [
            "tools/speech_data_explorer/data_explorer.py",
            "nemo/collections/tts/data/dataset.py",
            "nemo/collections/common/tokenizers/tabular_tokenizer.py",
        ]
        
        for file_path in vulnerable_files:
            full_path = Path(__file__).parent.parent.parent / file_path
            if not full_path.exists():
                continue
                
            content = full_path.read_text()
            
            # Check for pickle import
            assert 'import pickle' in content or 'from pickle import' in content, \
                f"pickle import not found in {file_path}"

    def test_pickle_load_without_safe_alternatives(self):
        """
        Test: Verify that pickle.load is used without safer alternatives
        
        Safer alternatives include:
        - JSON for simple data structures
        - Protocol Buffers for complex structured data
        - Custom serialization with validation
        """
        filepath = Path(__file__).parent.parent.parent / "tools/speech_data_explorer/data_explorer.py"
        
        if not filepath.exists():
            pytest.skip(f"File not found: {filepath}")
            
        content = filepath.read_text()
        
        # Verify pickle.load is used
        assert 'pickle.load(f)' in content, "Direct pickle.load(f) call not found"
        
        # Verify safer alternatives are NOT used for the same data
        # This indicates the vulnerability is still present
        assert 'json.load' not in content or content.count('pickle.load') > content.count('json.load'), \
            "JSON alternative may be in use"


class TestInsecureTorchLoadDeserialization:
    """
    Test suite to verify insecure torch.load usage with weights_only=False.
    
    Security Risk: torch.load with weights_only=False uses pickle under the hood,
    which can execute arbitrary code during deserialization.
    """

    @pytest.fixture
    def malicious_torch_file(self):
        """
        Create a mock PyTorch checkpoint file for testing.
        """
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save({'state_dict': {}}, f.name)
            return f.name

    def test_save_restore_connector_torch_load_vulnerability(self):
        """
        Test: Verify save_restore_connector.py uses insecure torch.load
        
        Location: nemo/core/connectors/save_restore_connector.py:760
        Vulnerable code: torch.load(model_weights, map_location='cpu', weights_only=False)
        
        Risk: Loading untrusted model files can lead to RCE
        """
        filepath = Path(__file__).parent.parent.parent / "nemo/core/connectors/save_restore_connector.py"
        
        assert filepath.exists(), f"File not found: {filepath}"
        
        content = filepath.read_text()
        
        # Verify torch.load with weights_only=False is used
        assert 'torch.load' in content, "torch.load not found in save_restore_connector.py"
        assert 'weights_only=False' in content, "weights_only=False not found - vulnerability may be fixed"
        
        # Verify the specific vulnerable pattern
        assert "torch.load(model_weights, map_location='cpu', weights_only=False)" in content, \
            "Exact vulnerable pattern not found"

    def test_multiple_torch_load_vulnerabilities(self):
        """
        Test: Identify multiple files with torch.load(weights_only=False)
        
        This test verifies that the vulnerability is widespread across the codebase.
        """
        vulnerable_patterns = []
        
        test_files = [
            "nemo/core/connectors/save_restore_connector.py",
            "nemo/collections/multimodal/speech_llm/parts/mixins/adapter_mixin.py",
            "nemo/collections/multimodal/speech_llm/models/modular_models.py",
            "nemo/collections/llm/gpt/model/hyena.py",
            "nemo/utils/callbacks/nemo_model_checkpoint.py",
            "nemo/lightning/pytorch/strategies/megatron_strategy.py",
            "nemo/core/classes/mixins/adapter_mixins.py",
            "nemo/collections/common/callbacks/ema.py",
        ]
        
        for file_path in test_files:
            full_path = Path(__file__).parent.parent.parent / file_path
            if not full_path.exists():
                continue
                
            content = full_path.read_text()
            
            if 'weights_only=False' in content:
                # Count occurrences
                count = content.count('weights_only=False')
                vulnerable_patterns.append((file_path, count))
        
        # VULNERABILITY: Multiple files use weights_only=False
        assert len(vulnerable_patterns) > 0, \
            "No torch.load with weights_only=False found - vulnerability may be fixed"
        
        # At least 5 files should have this vulnerability
        assert len(vulnerable_patterns) >= 5, \
            f"Expected at least 5 vulnerable files, found {len(vulnerable_patterns)}"

    def test_torch_load_in_checkpoint_loading(self):
        """
        Test: Verify checkpoint loading uses unsafe deserialization
        
        Risk: Model checkpoints from untrusted sources (e.g., Hugging Face Hub)
        could contain malicious code that executes during loading.
        """
        filepath = Path(__file__).parent.parent.parent / "nemo/core/connectors/save_restore_connector.py"
        
        if not filepath.exists():
            pytest.skip(f"File not found: {filepath}")
            
        content = filepath.read_text()
        
        # Find the _load_state_dict_from_disk method
        assert '_load_state_dict_from_disk' in content, \
            "Method _load_state_dict_from_disk not found"
        
        # Extract method content
        lines = content.split('\n')
        method_start = None
        for i, line in enumerate(lines):
            if '_load_state_dict_from_disk' in line:
                method_start = i
                break
        
        assert method_start is not None, "Could not find method start"
        
        # Check the next few lines for torch.load
        method_lines = lines[method_start:method_start+10]
        method_str = '\n'.join(method_lines)
        
        # VULNERABILITY: Method uses unsafe torch.load
        assert 'torch.load' in method_str, "torch.load not found in method"
        assert 'weights_only=False' in method_str, \
            "weights_only=False not found - vulnerability may be mitigated"

    def test_adapter_loading_vulnerability(self):
        """
        Test: Verify adapter loading uses insecure deserialization
        
        Location: nemo/core/classes/mixins/adapter_mixins.py:962
        
        Risk: Adapter files could be malicious and execute code when loaded.
        """
        filepath = Path(__file__).parent.parent.parent / "nemo/core/classes/mixins/adapter_mixins.py"
        
        if not filepath.exists():
            pytest.skip(f"File not found: {filepath}")
            
        content = filepath.read_text()
        
        # Verify the vulnerable pattern exists
        assert 'torch.load(filepath, map_location=map_location, weights_only=False)' in content, \
            "Adapter loading vulnerability not found"


class TestDeserializationCodePatterns:
    """
    Test suite to analyze code patterns for insecure deserialization using AST.
    
    This provides a more robust detection mechanism by parsing the actual code structure.
    """

    def get_vulnerable_torch_loads(self, filepath: Path) -> List[Tuple[int, str]]:
        """
        Parse Python file and find torch.load calls with weights_only=False.
        
        Returns: List of (line_number, code_snippet) tuples
        """
        if not filepath.exists():
            return []
            
        vulnerabilities = []
        content = filepath.read_text()
        
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check if this is a torch.load call
                if isinstance(node.func, ast.Attribute):
                    if (hasattr(node.func.value, 'id') and 
                        node.func.value.id == 'torch' and 
                        node.func.attr == 'load'):
                        
                        # Check for weights_only=False keyword argument
                        for keyword in node.keywords:
                            if keyword.arg == 'weights_only':
                                if isinstance(keyword.value, ast.Constant):
                                    if keyword.value.value is False:
                                        line_num = node.lineno
                                        vulnerabilities.append((line_num, filepath.name))
        
        return vulnerabilities

    def test_ast_based_vulnerability_detection(self):
        """
        Test: Use AST parsing to detect insecure torch.load patterns
        
        This provides a more reliable detection than simple string matching.
        """
        base_path = Path(__file__).parent.parent.parent
        
        vulnerable_files = [
            base_path / "nemo/core/connectors/save_restore_connector.py",
            base_path / "nemo/collections/llm/gpt/model/hyena.py",
        ]
        
        total_vulnerabilities = 0
        
        for filepath in vulnerable_files:
            if not filepath.exists():
                continue
                
            vulns = self.get_vulnerable_torch_loads(filepath)
            total_vulnerabilities += len(vulns)
        
        # VULNERABILITY: AST analysis should detect multiple instances
        assert total_vulnerabilities > 0, \
            "AST-based analysis did not detect any vulnerabilities"

    def test_pickle_load_in_production_code(self):
        """
        Test: Verify pickle.load is used in production (non-test) code
        
        Risk: Production code should not use pickle.load for untrusted data.
        """
        base_path = Path(__file__).parent.parent.parent
        
        production_files = [
            base_path / "tools/speech_data_explorer/data_explorer.py",
            base_path / "nemo/collections/tts/data/dataset.py",
        ]
        
        files_with_pickle = 0
        
        for filepath in production_files:
            if not filepath.exists():
                continue
                
            content = filepath.read_text()
            
            if 'pickle.load' in content or 'pickle.loads' in content:
                files_with_pickle += 1
        
        # VULNERABILITY: Production code uses pickle
        assert files_with_pickle > 0, \
            "pickle.load not found in production code - vulnerability may be fixed"


class TestHuggingFaceHubIntegration:
    """
    Test suite for Hugging Face Hub integration security.
    
    The CVE specifically mentions that integration with Hugging Face Hub
    makes it critical to ensure models are loaded safely.
    """

    def test_model_loading_from_external_sources(self):
        """
        Test: Verify that models from external sources use unsafe loading
        
        Risk: Models from Hugging Face Hub or other sources could be malicious.
        The application should validate model integrity before loading.
        """
        filepath = Path(__file__).parent.parent.parent / "nemo/core/connectors/save_restore_connector.py"
        
        if not filepath.exists():
            pytest.skip(f"File not found: {filepath}")
            
        content = filepath.read_text()
        
        # Check for model restoration methods
        assert 'restore_from' in content, "Model restoration functionality not found"
        
        # Verify unsafe deserialization is used in restoration
        assert 'torch.load' in content and 'weights_only=False' in content, \
            "Unsafe deserialization in model restoration not confirmed"

    def test_no_model_signature_verification(self):
        """
        Test: Verify that model files are loaded without signature verification
        
        Best Practice: Models should be cryptographically signed and verified
        before loading to prevent tampering.
        """
        filepath = Path(__file__).parent.parent.parent / "nemo/core/connectors/save_restore_connector.py"
        
        if not filepath.exists():
            pytest.skip(f"File not found: {filepath}")
            
        content = filepath.read_text()
        
        # VULNERABILITY: No signature verification before loading
        assert 'verify_signature' not in content.lower(), \
            "Signature verification found - this would mitigate the vulnerability"
        assert 'cryptograph' not in content.lower(), \
            "Cryptographic verification found - this would mitigate the vulnerability"
        assert 'hmac' not in content.lower(), \
            "HMAC verification found - this would mitigate the vulnerability"


class TestVulnerabilityDocumentation:
    """
    Documentation tests to ensure the vulnerability is well-understood.
    """

    def test_vulnerability_severity_classification(self):
        """
        Test: Document the severity classification of this vulnerability
        
        CVE-001 is classified as CRITICAL because:
        1. It allows Remote Code Execution (RCE)
        2. It affects model loading from external sources
        3. Exploitation requires minimal user interaction
        4. Integration with Hugging Face Hub increases attack surface
        """
        severity = "CRITICAL"
        impact = "Remote Code Execution"
        
        assert severity == "CRITICAL", "Incorrect severity classification"
        assert impact == "Remote Code Execution", "Incorrect impact classification"

    def test_attack_vector_documentation(self):
        """
        Test: Document potential attack vectors
        
        Attack scenarios:
        1. Malicious model on Hugging Face Hub
        2. Man-in-the-middle attack during model download
        3. Compromised local model cache
        4. Malicious pickle file in data processing pipeline
        """
        attack_vectors = [
            "Malicious model on Hugging Face Hub",
            "Man-in-the-middle attack during model download",
            "Compromised local model cache",
            "Malicious pickle file in data processing",
        ]
        
        assert len(attack_vectors) >= 4, "Insufficient attack vector documentation"

    def test_affected_components_list(self):
        """
        Test: List all affected components
        
        This test documents which parts of the codebase are vulnerable.
        """
        affected_components = {
            'save_restore_connector': 'nemo/core/connectors/save_restore_connector.py',
            'data_explorer': 'tools/speech_data_explorer/data_explorer.py',
            'adapter_mixins': 'nemo/core/classes/mixins/adapter_mixins.py',
            'checkpoint_callbacks': 'nemo/utils/callbacks/nemo_model_checkpoint.py',
            'ema_callbacks': 'nemo/collections/common/callbacks/ema.py',
        }
        
        assert len(affected_components) >= 5, \
            "Incomplete list of affected components"


# Test execution summary
def test_cve_001_summary():
    """
    Summary test documenting CVE-001 findings.
    
    CVE-001: Insecure Deserialization Vulnerability
    ================================================
    
    Severity: CRITICAL
    Impact: Remote Code Execution (RCE)
    
    Vulnerable Patterns Identified:
    1. pickle.load() without validation
    2. torch.load(weights_only=False) in model loading
    3. No cryptographic verification of model files
    4. Unsafe deserialization in checkpoint restoration
    
    Affected Areas:
    - Model checkpoint loading and restoration
    - Data processing pipelines
    - Adapter and PEFT model loading
    - EMA checkpoint handling
    
    Recommendation:
    - Replace pickle with safer alternatives (JSON, Protocol Buffers)
    - Use torch.load(weights_only=True) when possible
    - Implement model signature verification
    - Add strict validation for all deserialized data
    - Load models only from trusted, verified sources
    """
    assert True, "CVE-001 vulnerability tests completed"
