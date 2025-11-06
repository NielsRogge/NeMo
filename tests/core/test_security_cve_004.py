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
Security tests for CVE-004: Unsafe Hydra target instantiation vulnerability.

Tests the hardened _is_target_allowed function and safe_instantiate wrapper
to ensure unsafe targets are properly blocked while legitimate targets are allowed.
"""

import pytest
from omegaconf import DictConfig, OmegaConf

from nemo.core.classes.common import _is_target_allowed, safe_instantiate


class TestCVE004TargetValidation:
    """Test suite for CVE-004 target validation security."""

    @pytest.mark.unit
    def test_allowed_torch_nn_target(self):
        """Test that torch.nn targets are allowed."""
        assert _is_target_allowed("torch.nn.Linear")
        assert _is_target_allowed("torch.nn.Module")
        assert _is_target_allowed("torch.nn.ReLU")

    @pytest.mark.unit
    def test_allowed_nemo_collections_target(self):
        """Test that nemo.collections targets are allowed."""
        assert _is_target_allowed("nemo.collections.asr.modules.ConvASREncoder")
        assert _is_target_allowed("nemo.collections.common.tokenizers.sentencepiece_tokenizer.SentencePieceTokenizer")

    @pytest.mark.unit
    def test_allowed_nemo_core_target(self):
        """Test that nemo.core targets are allowed."""
        assert _is_target_allowed("nemo.core.classes.ModelPT")

    @pytest.mark.unit
    def test_allowed_lightning_target(self):
        """Test that lightning.pytorch targets are allowed."""
        assert _is_target_allowed("lightning.pytorch.callbacks.ModelCheckpoint")
        assert _is_target_allowed("lightning.pytorch.loggers.TensorBoardLogger")

    @pytest.mark.unit
    def test_allowed_torch_optim_target(self):
        """Test that torch.optim targets are allowed."""
        assert _is_target_allowed("torch.optim.Adam")
        assert _is_target_allowed("torch.optim.SGD")

    @pytest.mark.unit
    def test_disallowed_os_system(self):
        """Test that os.system is blocked (arbitrary command execution)."""
        assert not _is_target_allowed("os.system")

    @pytest.mark.unit
    def test_disallowed_subprocess_targets(self):
        """Test that subprocess targets are blocked."""
        assert not _is_target_allowed("subprocess.call")
        assert not _is_target_allowed("subprocess.run")
        assert not _is_target_allowed("subprocess.Popen")

    @pytest.mark.unit
    def test_disallowed_eval_exec(self):
        """Test that eval/exec are blocked."""
        assert not _is_target_allowed("builtins.eval")
        assert not _is_target_allowed("builtins.exec")

    @pytest.mark.unit
    def test_disallowed_arbitrary_module(self):
        """Test that arbitrary modules are blocked."""
        assert not _is_target_allowed("random.module.SomethingMalicious")
        assert not _is_target_allowed("malicious.module.BadClass")

    @pytest.mark.unit
    def test_disallowed_pickle(self):
        """Test that pickle targets are blocked (arbitrary code execution)."""
        assert not _is_target_allowed("pickle.loads")

    @pytest.mark.unit
    def test_disallowed_importlib(self):
        """Test that importlib dynamic imports are blocked."""
        assert not _is_target_allowed("importlib.import_module")

    @pytest.mark.unit
    def test_safe_instantiate_with_allowed_target(self):
        """Test safe_instantiate with an allowed target."""
        config = DictConfig({
            "_target_": "torch.nn.Linear",
            "in_features": 10,
            "out_features": 5
        })
        obj = safe_instantiate(config)
        assert obj is not None
        assert obj.in_features == 10
        assert obj.out_features == 5

    @pytest.mark.unit
    def test_safe_instantiate_blocks_unsafe_target(self):
        """Test that safe_instantiate blocks unsafe targets."""
        config = DictConfig({
            "_target_": "os.system",
            "command": "echo 'malicious'"
        })
        with pytest.raises(ValueError, match="Instantiation of unsafe target.*is blocked"):
            safe_instantiate(config)

    @pytest.mark.unit
    def test_safe_instantiate_with_nested_targets(self):
        """Test safe_instantiate validates nested _target_ fields."""
        config = DictConfig({
            "_target_": "torch.nn.Sequential",
            "modules": [
                {"_target_": "torch.nn.Linear", "in_features": 10, "out_features": 5},
                {"_target_": "torch.nn.ReLU"}
            ]
        })
        # This should work as all targets are safe
        obj = safe_instantiate(config)
        assert obj is not None

    @pytest.mark.unit
    def test_safe_instantiate_blocks_nested_unsafe_target(self):
        """Test that safe_instantiate blocks unsafe targets in nested configs."""
        config = DictConfig({
            "_target_": "torch.nn.Sequential",
            "modules": [
                {"_target_": "torch.nn.Linear", "in_features": 10, "out_features": 5},
                {"_target_": "os.system", "command": "malicious"}
            ]
        })
        with pytest.raises(ValueError, match="Instantiation of unsafe target.*is blocked"):
            safe_instantiate(config)

    @pytest.mark.unit
    def test_missing_dependency_nemo_target(self):
        """Test that NeMo targets with missing dependencies are handled gracefully."""
        # This tests a legitimate NeMo target that may have missing dependencies
        # The function should allow it based on prefix matching when dependencies are missing
        target = "nemo.collections.asr.modules.SomeModuleWithMissingDeps"
        # Should not raise an exception, but may return True based on prefix matching
        result = _is_target_allowed(target)
        # Result could be True (allowed based on prefix) or False (not found)
        # We just verify it doesn't crash
        assert isinstance(result, bool)
