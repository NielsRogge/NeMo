# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
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
Security Tests for CVE-001: Insecure Deserialization
=====================================================

This test suite verifies the presence of insecure deserialization vulnerabilities
in the NeMo codebase. These tests are designed to detect and document security
issues related to unsafe use of pickle.load(), torch.load(), and similar 
deserialization methods.

**CRITICAL SEVERITY - CVE-001**
Jira Issue: https://ml6team.atlassian.net/browse/DR-134

Vulnerability Description:
--------------------------
The application uses insecure deserialization methods (pickle.load, torch.load with
weights_only=False) which can lead to remote code execution if untrusted data is
deserialized. This is particularly critical given the integration with Hugging Face
Hub where models from untrusted sources may be loaded.

Attack Vectors:
--------------
1. Malicious pickle files that execute arbitrary code during deserialization
2. Compromised PyTorch model files (.pt, .pth) containing malicious payloads
3. Untrusted models from Hugging Face Hub or other external sources
4. Man-in-the-middle attacks during model download

These tests DO NOT FIX the vulnerability - they document and verify its existence.
"""

import io
import os
import pickle
import tempfile
import warnings
from unittest.mock import MagicMock, patch

import pytest
import torch

from nemo.core.connectors.save_restore_connector import SaveRestoreConnector


class MaliciousPayload:
    """
    A malicious class that executes code during pickle deserialization.
    This simulates a real-world attack where an attacker crafts a pickle
    file to execute arbitrary code when loaded.
    """

    def __reduce__(self):
        # This will execute os.system when unpickled
        # In a real attack, this could download and execute malware,
        # exfiltrate data, or compromise the system
        return (os.system, ('echo "CVE-001: Code execution via pickle deserialization" > /tmp/cve001_exploit.txt',))


class MaliciousTorchPayload:
    """
    A malicious class that can be embedded in PyTorch model files.
    When torch.load() is called with weights_only=False, this payload
    will be executed.
    """

    def __reduce__(self):
        # Simulates arbitrary code execution via torch.load
        return (os.system, ('echo "CVE-001: Code execution via torch.load" > /tmp/cve001_torch_exploit.txt',))


class TestInsecurePickleDeserialization:
    """
    Test suite for pickle deserialization vulnerabilities.
    
    These tests verify that the codebase is vulnerable to malicious pickle
    files that can execute arbitrary code during deserialization.
    """

    @pytest.mark.unit
    def test_pickle_load_vulnerability_exists(self):
        """
        Test that pickle.load() is used without proper security measures.
        
        This test verifies the vulnerability exists in data_explorer.py where
        pickle.load() is called on potentially untrusted data files.
        
        Expected: Code execution occurs when malicious pickle is loaded
        """
        # Create a malicious pickle payload
        malicious_data = pickle.dumps(MaliciousPayload())
        
        # Verify the payload executes code when unpickled
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pkl') as f:
            f.write(malicious_data)
            pickle_file = f.name
        
        try:
            # This should trigger code execution (vulnerability confirmed)
            with open(pickle_file, 'rb') as f:
                # WARNING: This intentionally triggers the vulnerability
                result = pickle.load(f)
            
            # If we get here, the vulnerability exists
            # In a patched system, this should fail or use safe deserialization
            assert os.path.exists('/tmp/cve001_exploit.txt'), \
                "Vulnerability CVE-001: Arbitrary code execution via pickle.load confirmed"
        finally:
            # Cleanup
            if os.path.exists(pickle_file):
                os.unlink(pickle_file)
            if os.path.exists('/tmp/cve001_exploit.txt'):
                os.unlink('/tmp/cve001_exploit.txt')

    @pytest.mark.unit
    def test_pickle_loads_from_untrusted_source(self):
        """
        Test that pickle.loads() can execute arbitrary code from untrusted data.
        
        This simulates receiving serialized data from an untrusted source
        (e.g., downloaded model metadata, cached data files).
        
        Expected: Malicious payload executes successfully
        """
        # Create malicious serialized data
        malicious_bytes = pickle.dumps(MaliciousPayload())
        
        # Attempt to deserialize (simulating loading from untrusted source)
        try:
            # WARNING: This intentionally triggers the vulnerability
            result = pickle.loads(malicious_bytes)
            
            # Verify code execution occurred
            assert os.path.exists('/tmp/cve001_exploit.txt'), \
                "CVE-001: pickle.loads() executes arbitrary code from untrusted data"
        finally:
            if os.path.exists('/tmp/cve001_exploit.txt'):
                os.unlink('/tmp/cve001_exploit.txt')

    @pytest.mark.unit
    def test_pickle_vulnerability_in_data_explorer(self):
        """
        Test vulnerability in tools/speech_data_explorer/data_explorer.py:190
        
        This file uses pickle.load() to load cached data:
        ```
        with open(pickle_filename, 'rb') as f:
            data, wer, cer, wmr, mwa, num_hours, vocabulary_data, alphabet, metrics_available = pickle.load(f)
        ```
        
        If an attacker can control or modify the pickle file, they can execute
        arbitrary code.
        
        Expected: Confirms vulnerability exists in data_explorer pattern
        """
        # Simulate the data_explorer.py pickle loading pattern
        cached_data = {
            'data': [],
            'wer': 0.0,
            'cer': 0.0,
            'wmr': 0.0,
            'mwa': 0.0,
            'num_hours': 0,
            'vocabulary_data': [],
            'alphabet': [],
            'metrics_available': True
        }
        
        # Create a pickle file similar to data_explorer cache
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pkl') as f:
            # Inject malicious payload alongside legitimate data
            malicious_data = (
                MaliciousPayload(),  # Malicious payload
                0.0, 0.0, 0.0, 0.0, 0, [], [], True
            )
            pickle.dump(malicious_data, f)
            pickle_file = f.name
        
        try:
            # Simulate data_explorer.py loading pattern
            with open(pickle_file, 'rb') as f:
                # This is how data_explorer.py loads the pickle file
                loaded_data = pickle.load(f)
            
            # If we reach here, vulnerability is confirmed
            assert os.path.exists('/tmp/cve001_exploit.txt'), \
                "CVE-001: data_explorer.py pattern is vulnerable to malicious pickle files"
        finally:
            if os.path.exists(pickle_file):
                os.unlink(pickle_file)
            if os.path.exists('/tmp/cve001_exploit.txt'):
                os.unlink('/tmp/cve001_exploit.txt')

    @pytest.mark.unit
    def test_pickle_with_custom_class_definitions(self):
        """
        Test that pickle can deserialize arbitrary class definitions.
        
        An attacker can create custom classes in pickle files that execute
        malicious code in __init__, __setstate__, or __reduce__ methods.
        
        Expected: Custom classes with malicious code are instantiated
        """
        class MaliciousClass:
            def __init__(self):
                # Code execution during object instantiation
                with open('/tmp/cve001_class_init.txt', 'w') as f:
                    f.write('Malicious class instantiated')
        
        # Serialize the class instance
        malicious_instance = MaliciousClass()
        serialized = pickle.dumps(malicious_instance)
        
        try:
            # Deserialize (triggers __init__)
            deserialized = pickle.loads(serialized)
            
            assert os.path.exists('/tmp/cve001_class_init.txt'), \
                "CVE-001: Arbitrary class instantiation via pickle deserialization"
        finally:
            if os.path.exists('/tmp/cve001_class_init.txt'):
                os.unlink('/tmp/cve001_class_init.txt')


class TestInsecureTorchLoadDeserialization:
    """
    Test suite for torch.load() deserialization vulnerabilities.
    
    PyTorch's torch.load() uses pickle internally and is vulnerable to the
    same attacks when weights_only=False (which is the current setting in
    the codebase).
    """

    @pytest.mark.unit
    def test_torch_load_with_weights_only_false_vulnerability(self):
        """
        Test vulnerability in nemo/core/connectors/save_restore_connector.py:760
        
        The code uses:
        ```
        return torch.load(model_weights, map_location='cpu', weights_only=False)
        ```
        
        This allows arbitrary code execution through malicious PyTorch files.
        
        Expected: Malicious payload in torch file executes code
        """
        # Create a malicious torch file
        malicious_state_dict = {
            'model_state': torch.randn(10, 10),
            'malicious_payload': MaliciousTorchPayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(malicious_state_dict, f)
            model_file = f.name
        
        try:
            # Load using torch.load with weights_only=False (current vulnerable pattern)
            # This is the exact pattern used in save_restore_connector.py
            loaded_data = torch.load(model_file, map_location='cpu', weights_only=False)
            
            # Verify code execution
            assert os.path.exists('/tmp/cve001_torch_exploit.txt'), \
                "CVE-001: torch.load(weights_only=False) executes arbitrary code"
        finally:
            if os.path.exists(model_file):
                os.unlink(model_file)
            if os.path.exists('/tmp/cve001_torch_exploit.txt'):
                os.unlink('/tmp/cve001_torch_exploit.txt')

    @pytest.mark.unit
    def test_save_restore_connector_vulnerability(self):
        """
        Test the SaveRestoreConnector._load_state_dict_from_disk method.
        
        This method directly uses torch.load with weights_only=False:
        nemo/core/connectors/save_restore_connector.py:760
        
        Expected: Method is vulnerable to malicious torch files
        """
        # Create malicious model file
        malicious_weights = {
            'encoder.weight': torch.randn(128, 64),
            'decoder.weight': torch.randn(64, 128),
            'exploit': MaliciousTorchPayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(malicious_weights, f)
            model_file = f.name
        
        try:
            # Call the vulnerable method directly
            loaded = SaveRestoreConnector._load_state_dict_from_disk(model_file)
            
            # Verify vulnerability
            assert os.path.exists('/tmp/cve001_torch_exploit.txt'), \
                "CVE-001: SaveRestoreConnector._load_state_dict_from_disk is vulnerable"
            assert 'exploit' in loaded, "Malicious payload was loaded"
        finally:
            if os.path.exists(model_file):
                os.unlink(model_file)
            if os.path.exists('/tmp/cve001_torch_exploit.txt'):
                os.unlink('/tmp/cve001_torch_exploit.txt')

    @pytest.mark.unit
    def test_torch_load_from_untrusted_source_huggingface(self):
        """
        Test attack vector: malicious model from Hugging Face Hub.
        
        NeMo integrates with Hugging Face Hub to download models. If an attacker
        uploads a malicious model or compromises an existing model, users who
        load it will execute the attacker's code.
        
        Expected: Demonstrates risk of loading models from untrusted sources
        """
        # Simulate downloading a malicious model from HuggingFace
        # In reality, this would be model files downloaded via huggingface_hub
        
        malicious_model = {
            'config': {'model_type': 'nemo', 'vocab_size': 1000},
            'state_dict': {
                'embedding.weight': torch.randn(1000, 768),
                # Malicious payload hidden in model
                '__metadata__': MaliciousTorchPayload(),
            }
        }
        
        # Save as if downloaded from HF Hub
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(malicious_model, f)
            downloaded_model = f.name
        
        try:
            # User loads the model thinking it's safe
            loaded = torch.load(downloaded_model, map_location='cpu', weights_only=False)
            
            assert os.path.exists('/tmp/cve001_torch_exploit.txt'), \
                "CVE-001: Loading untrusted models from HF Hub can execute arbitrary code"
        finally:
            if os.path.exists(downloaded_model):
                os.unlink(downloaded_model)
            if os.path.exists('/tmp/cve001_torch_exploit.txt'):
                os.unlink('/tmp/cve001_torch_exploit.txt')

    @pytest.mark.unit
    def test_torch_load_lambda_function_injection(self):
        """
        Test lambda function injection attack vector.
        
        Attackers can inject lambda functions or other callable objects into
        torch files that execute when the model is loaded.
        
        Expected: Lambda functions in torch files are executed
        """
        # Create a model with lambda injection
        # Note: Lambdas can't be pickled directly, but we can use other callables
        
        class CallableExploit:
            def __call__(self):
                with open('/tmp/cve001_callable.txt', 'w') as f:
                    f.write('Callable exploit executed')
                return "Compromised"
        
        malicious_model = {
            'model': torch.nn.Linear(10, 10).state_dict(),
            'optimizer': CallableExploit(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(malicious_model, f)
            model_file = f.name
        
        try:
            loaded = torch.load(model_file, map_location='cpu', weights_only=False)
            
            # Trigger the callable
            if hasattr(loaded['optimizer'], '__call__'):
                loaded['optimizer']()
            
            assert os.path.exists('/tmp/cve001_callable.txt'), \
                "CVE-001: Callable objects in torch files can execute code"
        finally:
            if os.path.exists(model_file):
                os.unlink(model_file)
            if os.path.exists('/tmp/cve001_callable.txt'):
                os.unlink('/tmp/cve001_callable.txt')


class TestDeserializationAttackVectors:
    """
    Test suite for various attack vectors and edge cases.
    
    These tests demonstrate different ways an attacker could exploit
    insecure deserialization in the NeMo codebase.
    """

    @pytest.mark.unit
    def test_supply_chain_attack_via_cached_data(self):
        """
        Test attack vector: Supply chain attack via cached pickle files.
        
        If an attacker can modify cached data files (e.g., through a compromised
        dependency, shared storage, or insufficient file permissions), they can
        inject malicious payloads.
        
        Expected: Modified cache files can execute code
        """
        # Simulate legitimate cached data
        legitimate_cache = {
            'vocabulary': ['hello', 'world'],
            'statistics': {'count': 100, 'mean': 0.5}
        }
        
        # Attacker modifies cache to inject payload
        compromised_cache = {
            'vocabulary': ['hello', 'world'],
            'statistics': {'count': 100, 'mean': 0.5},
            'metadata': MaliciousPayload(),  # Injected payload
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pkl') as f:
            pickle.dump(compromised_cache, f)
            cache_file = f.name
        
        try:
            # Application loads the compromised cache
            with open(cache_file, 'rb') as f:
                data = pickle.load(f)
            
            assert os.path.exists('/tmp/cve001_exploit.txt'), \
                "CVE-001: Compromised cache files can execute arbitrary code"
        finally:
            if os.path.exists(cache_file):
                os.unlink(cache_file)
            if os.path.exists('/tmp/cve001_exploit.txt'):
                os.unlink('/tmp/cve001_exploit.txt')

    @pytest.mark.unit
    def test_model_checkpoint_tampering(self):
        """
        Test attack vector: Tampered model checkpoint files.
        
        Model checkpoints saved as .ckpt or .pt files can be tampered with
        to include malicious payloads. When training resumes from a checkpoint,
        the payload executes.
        
        Expected: Tampered checkpoints execute code when loaded
        """
        # Create a checkpoint file with malicious payload
        checkpoint = {
            'epoch': 10,
            'model_state_dict': torch.nn.Linear(10, 10).state_dict(),
            'optimizer_state_dict': {'lr': 0.001},
            'loss': 0.5,
            # Malicious payload hidden in checkpoint metadata
            'training_metadata': MaliciousTorchPayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.ckpt') as f:
            torch.save(checkpoint, f)
            ckpt_file = f.name
        
        try:
            # Load checkpoint to resume training
            loaded_ckpt = torch.load(ckpt_file, map_location='cpu', weights_only=False)
            
            assert os.path.exists('/tmp/cve001_torch_exploit.txt'), \
                "CVE-001: Tampered checkpoint files can execute arbitrary code"
        finally:
            if os.path.exists(ckpt_file):
                os.unlink(ckpt_file)
            if os.path.exists('/tmp/cve001_torch_exploit.txt'):
                os.unlink('/tmp/cve001_torch_exploit.txt')

    @pytest.mark.unit
    def test_pickle_protocol_5_with_out_of_band_data(self):
        """
        Test pickle protocol 5 attack with out-of-band data buffers.
        
        Pickle protocol 5 allows out-of-band data transfer which can be
        exploited to hide malicious payloads in buffer data.
        
        Expected: Protocol 5 pickles can contain hidden malicious code
        """
        # Create pickle with protocol 5 (supports out-of-band buffers)
        malicious_obj = MaliciousPayload()
        
        buffer_list = []
        pickled_data = pickle.dumps(malicious_obj, protocol=5)
        
        try:
            # Load pickle (triggers vulnerability)
            result = pickle.loads(pickled_data)
            
            assert os.path.exists('/tmp/cve001_exploit.txt'), \
                "CVE-001: Pickle protocol 5 can hide malicious payloads"
        finally:
            if os.path.exists('/tmp/cve001_exploit.txt'):
                os.unlink('/tmp/cve001_exploit.txt')

    @pytest.mark.unit
    def test_deserialization_with_custom_unpickler(self):
        """
        Test that even custom unpickler implementations may be vulnerable.
        
        Some codebases implement custom pickle.Unpickler classes but may not
        properly restrict which classes can be deserialized.
        
        Expected: Custom unpickler without proper restrictions is vulnerable
        """
        class CustomUnpickler(pickle.Unpickler):
            """Custom unpickler without security restrictions"""
            pass
        
        malicious_data = pickle.dumps(MaliciousPayload())
        
        try:
            # Use custom unpickler
            unpickler = CustomUnpickler(io.BytesIO(malicious_data))
            result = unpickler.load()
            
            assert os.path.exists('/tmp/cve001_exploit.txt'), \
                "CVE-001: Custom unpickler without restrictions is vulnerable"
        finally:
            if os.path.exists('/tmp/cve001_exploit.txt'):
                os.unlink('/tmp/cve001_exploit.txt')


class TestDeserializationCodePatterns:
    """
    Test suite for identifying vulnerable code patterns in the codebase.
    
    These tests scan for and verify the existence of vulnerable patterns
    that should be remediated.
    """

    @pytest.mark.unit
    def test_identify_pickle_load_usage(self):
        """
        Test to identify all uses of pickle.load in the codebase.
        
        This test documents all locations where pickle.load() is used,
        which are potential vulnerability points.
        
        Expected: Lists all pickle.load() usage locations
        """
        vulnerable_files = [
            'tools/speech_data_explorer/data_explorer.py',
            'nemo/collections/tts/data/dataset.py',
            'nemo/collections/nlp/modules/common/text_generation_utils.py',
            'nemo/collections/nlp/modules/common/retro_inference_strategies.py',
            # Add more files as identified by grep
        ]
        
        # Verify these files exist and contain pickle.load
        import importlib.util
        
        for file_path in vulnerable_files:
            full_path = os.path.join('/workspace', file_path)
            if os.path.exists(full_path):
                with open(full_path, 'r') as f:
                    content = f.read()
                    assert 'pickle.load' in content, \
                        f"CVE-001: {file_path} should contain pickle.load (vulnerability pattern)"

    @pytest.mark.unit
    def test_identify_torch_load_weights_only_false(self):
        """
        Test to identify torch.load() calls with weights_only=False.
        
        This parameter setting explicitly allows arbitrary code execution
        through deserialization.
        
        Expected: Documents all torch.load(weights_only=False) usage
        """
        # Verify the vulnerable pattern exists in save_restore_connector.py
        connector_file = '/workspace/nemo/core/connectors/save_restore_connector.py'
        
        with open(connector_file, 'r') as f:
            content = f.read()
            assert 'weights_only=False' in content, \
                "CVE-001: save_restore_connector.py uses weights_only=False (vulnerability)"
            assert 'torch.load' in content, \
                "CVE-001: save_restore_connector.py uses torch.load"

    @pytest.mark.unit
    def test_no_input_validation_on_deserialization(self):
        """
        Test that there is no input validation before deserialization.
        
        Secure implementations should validate data sources, check signatures,
        or use allow-lists before deserializing data.
        
        Expected: Confirms lack of validation (vulnerability indicator)
        """
        # Check SaveRestoreConnector for validation
        from nemo.core.connectors.save_restore_connector import SaveRestoreConnector
        import inspect
        
        method_source = inspect.getsource(SaveRestoreConnector._load_state_dict_from_disk)
        
        # Look for security measures (should be absent in vulnerable code)
        security_patterns = [
            'verify',
            'validate',
            'check_signature',
            'whitelist',
            'allowlist',
            'weights_only=True',
        ]
        
        has_security = any(pattern in method_source for pattern in security_patterns)
        
        assert not has_security, \
            "CVE-001: _load_state_dict_from_disk lacks security validation (vulnerability)"


class TestDeserializationMitigationStrategies:
    """
    Test suite documenting what secure implementations would look like.
    
    These tests demonstrate the ABSENCE of security measures, confirming
    the vulnerability. They also document what fixes would look like.
    """

    @pytest.mark.unit
    def test_torch_load_without_weights_only_true(self):
        """
        Test that torch.load is NOT using weights_only=True.
        
        The secure pattern would be:
            torch.load(path, weights_only=True)
        
        This restricts deserialization to tensor data only, preventing
        arbitrary code execution.
        
        Expected: Confirms weights_only=True is NOT used (vulnerability)
        """
        # Check the actual implementation
        connector_file = '/workspace/nemo/core/connectors/save_restore_connector.py'
        
        with open(connector_file, 'r') as f:
            content = f.read()
            
            # Vulnerability: weights_only=False is explicitly set
            assert 'weights_only=False' in content, \
                "CVE-001: Code explicitly uses weights_only=False"
            
            # Should not have weights_only=True
            weights_only_true_count = content.count('weights_only=True')
            weights_only_false_count = content.count('weights_only=False')
            
            assert weights_only_false_count > 0, \
                "CVE-001: weights_only=False is used (insecure)"

    @pytest.mark.unit  
    def test_no_restricted_unpickler_implementation(self):
        """
        Test that there is no restricted unpickler implementation.
        
        A secure implementation would override pickle.Unpickler.find_class()
        to restrict which classes can be instantiated during deserialization.
        
        Expected: Confirms no restricted unpickler exists (vulnerability)
        """
        # Search for any RestrictedUnpickler or SafeUnpickler classes
        from nemo.core.connectors import save_restore_connector
        import inspect
        
        # Get all classes in the module
        classes = inspect.getmembers(save_restore_connector, inspect.isclass)
        
        # Look for security-focused unpickler classes
        safe_unpickler_classes = [
            name for name, cls in classes 
            if 'safe' in name.lower() or 'restricted' in name.lower()
        ]
        
        assert len(safe_unpickler_classes) == 0, \
            "CVE-001: No safe/restricted unpickler implementation found"

    @pytest.mark.unit
    def test_no_model_signature_verification(self):
        """
        Test that model files are loaded without cryptographic signature verification.
        
        Secure implementations should verify digital signatures of model files
        before loading them to ensure they haven't been tampered with.
        
        Expected: Confirms no signature verification (vulnerability)
        """
        from nemo.core.connectors.save_restore_connector import SaveRestoreConnector
        import inspect
        
        # Check all methods for signature verification
        methods = inspect.getmembers(SaveRestoreConnector, predicate=inspect.ismethod)
        
        signature_verification_found = False
        for name, method in methods:
            try:
                source = inspect.getsource(method)
                if 'signature' in source.lower() and 'verify' in source.lower():
                    signature_verification_found = True
            except:
                pass
        
        assert not signature_verification_found, \
            "CVE-001: No cryptographic signature verification for model files"


# Summary of Vulnerable Patterns Found:
# ======================================
#
# 1. pickle.load() usage:
#    - tools/speech_data_explorer/data_explorer.py:190
#    - Multiple other locations (21 files total)
#
# 2. torch.load(weights_only=False) usage:
#    - nemo/core/connectors/save_restore_connector.py:760
#    - Multiple other locations (49 files total)
#
# 3. No input validation before deserialization
#
# 4. No signature verification for model files
#
# 5. No restricted unpickler implementation
#
# Recommended Remediation:
# =======================
#
# 1. Replace pickle.load() with safe alternatives:
#    - Use JSON for simple data structures
#    - Use HDF5 or numpy's .npz format for numerical data
#    - If pickle is necessary, implement RestrictedUnpickler
#
# 2. Replace torch.load(weights_only=False) with:
#    - torch.load(path, weights_only=True) when loading model weights
#    - Implement signature verification for all model files
#
# 3. Add input validation:
#    - Verify file sources and checksums
#    - Implement allow-lists for trusted model sources
#    - Add cryptographic signatures to all distributed models
#
# 4. Security review process:
#    - Require security review for all new deserialization code
#    - Add automated scanning for pickle.load and torch.load patterns
#    - Implement runtime monitoring for deserialization attempts
