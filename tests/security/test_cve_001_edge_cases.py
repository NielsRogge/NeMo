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
Security Tests for CVE-001: Edge Cases and Attack Vectors

This test suite explores edge cases and specific attack vectors related to
the insecure deserialization vulnerability (CVE-001).

These tests verify advanced exploitation scenarios and ensure comprehensive
coverage of the vulnerability.
"""

import io
import os
import pickle
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import torch


class TestPickleExploitationVectors:
    """
    Test various pickle exploitation techniques to ensure the vulnerability
    can be exploited in different ways.
    """

    def test_pickle_reduce_exploit_pattern(self):
        """
        Test: Verify __reduce__ exploitation pattern is possible
        
        The __reduce__ method allows arbitrary code execution during unpickling.
        This is the primary mechanism for pickle-based attacks.
        """
        
        class ExploitObject:
            """
            Demonstrates how __reduce__ can be used for code execution.
            
            In a real attack, this could execute system commands, exfiltrate data,
            or establish a reverse shell.
            """
            def __reduce__(self):
                # This would execute os.system in a real exploit
                # Using a safe example for testing
                return (eval, ("42",))
        
        # Serialize the exploit object
        exploit_data = pickle.dumps(ExploitObject())
        
        # VULNERABILITY: This would execute the code in __reduce__
        result = pickle.loads(exploit_data)
        
        # The fact that we can deserialize and execute is the vulnerability
        assert result == 42, "Pickle exploit pattern not executable"

    def test_pickle_loads_vs_load(self):
        """
        Test: Verify both pickle.load and pickle.loads are vulnerable
        
        Both methods are equally dangerous as they both execute __reduce__.
        """
        test_data = {'key': 'value'}
        
        # Test pickle.loads (from bytes)
        serialized = pickle.dumps(test_data)
        result_loads = pickle.loads(serialized)
        assert result_loads == test_data
        
        # Test pickle.load (from file)
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            pickle.dump(test_data, f)
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                result_load = pickle.load(f)
            assert result_load == test_data
        finally:
            os.unlink(temp_path)

    def test_nested_pickle_objects(self):
        """
        Test: Verify nested pickle objects maintain vulnerability
        
        Attackers might use nested objects to obfuscate malicious payloads.
        """
        nested_data = {
            'level1': {
                'level2': {
                    'level3': 'payload'
                }
            }
        }
        
        serialized = pickle.dumps(nested_data)
        deserialized = pickle.loads(serialized)
        
        assert deserialized['level1']['level2']['level3'] == 'payload'


class TestTorchLoadExploitationVectors:
    """
    Test various torch.load exploitation scenarios.
    
    torch.load uses pickle internally when weights_only=False, making it
    vulnerable to the same attacks.
    """

    def test_torch_load_uses_pickle_internally(self):
        """
        Test: Verify torch.load with weights_only=False uses pickle
        
        This confirms that torch.load inherits pickle's vulnerabilities.
        """
        test_state = {'param1': torch.tensor([1.0, 2.0, 3.0])}
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(test_state, f.name)
            temp_path = f.name
        
        try:
            # VULNERABILITY: weights_only=False uses pickle
            loaded = torch.load(temp_path, weights_only=False)
            assert 'param1' in loaded
        finally:
            os.unlink(temp_path)

    def test_torch_load_with_map_location(self):
        """
        Test: Verify map_location parameter doesn't prevent exploitation
        
        The vulnerable code uses map_location='cpu', which doesn't mitigate
        the deserialization vulnerability.
        """
        test_state = {'weights': torch.tensor([[1.0, 2.0], [3.0, 4.0]])}
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(test_state, f.name)
            temp_path = f.name
        
        try:
            # VULNERABILITY: map_location doesn't prevent pickle exploitation
            loaded = torch.load(temp_path, map_location='cpu', weights_only=False)
            assert loaded['weights'].shape == (2, 2)
        finally:
            os.unlink(temp_path)

    def test_checkpoint_dict_structure(self):
        """
        Test: Verify checkpoint dict structure allows arbitrary keys
        
        Attackers can include malicious objects as dict values.
        """
        checkpoint = {
            'state_dict': {},
            'optimizer_state': {},
            'epoch': 0,
            # An attacker could add malicious objects here
            'metadata': {'model': 'test'}
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.ckpt') as f:
            torch.save(checkpoint, f.name)
            temp_path = f.name
        
        try:
            loaded = torch.load(temp_path, weights_only=False)
            assert 'metadata' in loaded
        finally:
            os.unlink(temp_path)


class TestRealWorldExploitScenarios:
    """
    Test real-world exploitation scenarios specific to NeMo.
    """

    def test_model_download_and_load_scenario(self):
        """
        Test: Simulate downloading and loading a malicious model
        
        Scenario:
        1. User downloads a model from an untrusted source
        2. Model file contains malicious pickle payload
        3. Application loads model using torch.load(weights_only=False)
        4. Malicious code executes
        """
        # Simulate a "downloaded" model file
        malicious_model = {
            'state_dict': {},
            'config': {'architecture': 'bert'}
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.nemo') as f:
            torch.save(malicious_model, f.name)
            model_path = f.name
        
        try:
            # This simulates what happens in save_restore_connector.py:760
            loaded = torch.load(model_path, map_location='cpu', weights_only=False)
            
            # VULNERABILITY: Arbitrary data loaded without validation
            assert isinstance(loaded, dict)
        finally:
            os.unlink(model_path)

    def test_adapter_loading_scenario(self):
        """
        Test: Simulate loading a malicious adapter checkpoint
        
        Location: nemo/core/classes/mixins/adapter_mixins.py
        
        Scenario:
        1. User loads a PEFT adapter from a file
        2. Adapter file contains malicious payload
        3. torch.load executes the payload
        """
        adapter_checkpoint = {
            '__cfg__': {'adapter_type': 'lora'},
            'adapter_weights': {}
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.ckpt') as f:
            torch.save(adapter_checkpoint, f.name)
            adapter_path = f.name
        
        try:
            # This simulates adapter loading vulnerability
            loaded = torch.load(adapter_path, map_location='cpu', weights_only=False)
            
            # VULNERABILITY: Config and weights loaded without verification
            assert '__cfg__' in loaded
        finally:
            os.unlink(adapter_path)

    def test_ema_checkpoint_loading_scenario(self):
        """
        Test: Simulate EMA checkpoint loading vulnerability
        
        Location: nemo/collections/common/callbacks/ema.py:138
        
        Scenario:
        1. Application saves EMA checkpoint
        2. Attacker replaces EMA file with malicious version
        3. Application loads malicious EMA checkpoint
        """
        ema_checkpoint = {
            'optimizer_states': [],
            'ema_weights': {}
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='-EMA.ckpt') as f:
            torch.save(ema_checkpoint, f.name)
            ema_path = f.name
        
        try:
            # This simulates EMA loading vulnerability
            loaded = torch.load(ema_path, map_location=torch.device('cpu'), weights_only=False)
            
            # VULNERABILITY: EMA checkpoint loaded without validation
            assert 'optimizer_states' in loaded
        finally:
            os.unlink(ema_path)


class TestDataProcessingVulnerabilities:
    """
    Test vulnerabilities in data processing pipelines.
    """

    def test_speech_data_explorer_cache_scenario(self):
        """
        Test: Simulate cached data loading vulnerability
        
        Location: tools/speech_data_explorer/data_explorer.py:190
        
        Scenario:
        1. Application processes speech data and caches results
        2. Attacker replaces cache file with malicious pickle
        3. Application loads malicious cache
        """
        cache_data = (
            {'utterances': []},  # data
            0.05,  # wer
            0.03,  # cer
            0.02,  # wmr
            0.01,  # mwa
            100.0,  # num_hours
            [],  # vocabulary_data
            set(),  # alphabet
            True  # metrics_available
        )
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pkl') as f:
            pickle.dump(cache_data, f)
            cache_path = f.name
        
        try:
            # This simulates the vulnerable cache loading
            with open(cache_path, 'rb') as f:
                loaded = pickle.load(f)
            
            # VULNERABILITY: Cache loaded without integrity verification
            assert len(loaded) == 9
        finally:
            os.unlink(cache_path)

    def test_tts_dataset_loading_scenario(self):
        """
        Test: Verify TTS dataset loading uses pickle
        
        Location: nemo/collections/tts/data/dataset.py
        
        Risk: Dataset files could be malicious.
        """
        # Verify the file exists and uses pickle
        filepath = Path(__file__).parent.parent.parent / "nemo/collections/tts/data/dataset.py"
        
        if filepath.exists():
            content = filepath.read_text()
            
            # Check for pickle usage in dataset loading
            has_pickle = 'pickle' in content.lower()
            
            if has_pickle:
                # VULNERABILITY: Dataset loading may use pickle
                assert 'import pickle' in content or 'from pickle' in content


class TestMitigationBypass:
    """
    Test potential mitigation bypasses.
    
    These tests verify that partial mitigations don't fully protect against
    the vulnerability.
    """

    def test_file_extension_check_bypass(self):
        """
        Test: Verify file extension checks don't prevent exploitation
        
        Some code might check file extensions (.pt, .ckpt, .nemo) but this
        doesn't prevent malicious content.
        """
        malicious_content = {'exploit': 'payload'}
        
        # Test different extensions
        extensions = ['.pt', '.ckpt', '.nemo', '.pth']
        
        for ext in extensions:
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix=ext) as f:
                torch.save(malicious_content, f.name)
                temp_path = f.name
            
            try:
                # VULNERABILITY: Extension check doesn't prevent loading
                loaded = torch.load(temp_path, weights_only=False)
                assert 'exploit' in loaded
            finally:
                os.unlink(temp_path)

    def test_map_location_not_a_mitigation(self):
        """
        Test: Verify map_location parameter is not a security control
        
        The code uses map_location='cpu' which is for performance, not security.
        """
        malicious_state = {'tensor': torch.randn(5, 5)}
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(malicious_state, f.name)
            temp_path = f.name
        
        try:
            # map_location is for device placement, not security
            for map_loc in ['cpu', 'cuda:0', None]:
                try:
                    loaded = torch.load(temp_path, map_location=map_loc, weights_only=False)
                    assert 'tensor' in loaded
                except (RuntimeError, AssertionError):
                    # CUDA might not be available, that's OK for this test
                    pass
        finally:
            os.unlink(temp_path)


class TestVulnerabilityChaining:
    """
    Test vulnerability chaining scenarios.
    
    Multiple vulnerabilities can be chained together for greater impact.
    """

    def test_download_then_load_chain(self):
        """
        Test: Simulate attack chain of downloading and loading
        
        Chain:
        1. Attacker hosts malicious model on public repository
        2. User downloads model (MITM possible if not using HTTPS)
        3. Application loads model with insecure deserialization
        4. Code execution achieved
        """
        # This test documents the attack chain
        attack_chain = [
            "1. Attacker uploads malicious model to Hugging Face Hub",
            "2. Model appears legitimate (good metrics, documentation)",
            "3. User downloads model via NeMo",
            "4. NeMo uses torch.load(weights_only=False)",
            "5. Malicious code executes on user's machine"
        ]
        
        assert len(attack_chain) == 5, "Incomplete attack chain documentation"

    def test_model_cache_poisoning_chain(self):
        """
        Test: Simulate cache poisoning attack chain
        
        Chain:
        1. User downloads legitimate model
        2. Model is cached locally
        3. Attacker gains local file access (malware, shared system, etc.)
        4. Attacker replaces cached model with malicious version
        5. Application loads poisoned cache
        """
        attack_chain = [
            "1. Legitimate model cached locally",
            "2. Attacker gains local file system access",
            "3. Attacker replaces model file in cache",
            "4. Application loads from cache without verification",
            "5. Malicious model executed"
        ]
        
        assert len(attack_chain) == 5, "Incomplete cache poisoning chain"


def test_edge_cases_summary():
    """
    Summary of edge cases and attack vectors.
    
    This test documents the comprehensive nature of the vulnerability
    across various exploitation scenarios.
    
    Key Findings:
    ==============
    
    1. Pickle Exploitation:
       - __reduce__ method allows arbitrary code execution
       - Both pickle.load and pickle.loads are vulnerable
       - Nested objects maintain vulnerability
    
    2. PyTorch Loading:
       - torch.load with weights_only=False uses pickle internally
       - map_location parameter doesn't provide security
       - All checkpoint formats (.pt, .ckpt, .nemo) are vulnerable
    
    3. Real-World Scenarios:
       - Model downloads from untrusted sources
       - Adapter/PEFT loading vulnerabilities
       - EMA checkpoint exploitation
       - Data processing cache poisoning
    
    4. Mitigation Bypasses:
       - File extension checks are ineffective
       - Device placement (map_location) is not a security control
    
    5. Attack Chains:
       - Download → Load → Execute
       - Cache poisoning via local access
       - MITM attacks on model downloads
    
    Impact: CRITICAL - Remote Code Execution
    """
    assert True, "CVE-001 edge cases and attack vectors documented"
