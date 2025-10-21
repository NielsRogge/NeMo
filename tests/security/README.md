# Security Tests for NeMo

This directory contains security-focused test suites designed to identify and document vulnerabilities in the NeMo codebase.

## CVE-001: Insecure Deserialization

**Severity:** CRITICAL  
**Impact:** Remote Code Execution (RCE)  
**Jira Issue:** https://ml6team.atlassian.net/browse/DR-134

### Overview

CVE-001 identifies critical insecure deserialization vulnerabilities in the NeMo codebase. The application uses `pickle.load()`, `pickle.loads()`, and `torch.load(weights_only=False)` to deserialize data without proper validation, which can lead to arbitrary code execution.

### Vulnerability Details

The vulnerability manifests in several ways:

1. **Pickle Deserialization**
   - `pickle.load()` and `pickle.loads()` can execute arbitrary code through the `__reduce__` method
   - Used in data processing pipelines without validation
   - Example: `tools/speech_data_explorer/data_explorer.py:190`

2. **PyTorch Model Loading**
   - `torch.load(weights_only=False)` uses pickle internally
   - Used for loading model checkpoints, adapters, and EMA weights
   - Example: `nemo/core/connectors/save_restore_connector.py:760`

3. **Hugging Face Hub Integration**
   - Models downloaded from Hugging Face Hub are loaded without signature verification
   - No integrity checks before deserialization
   - Increases attack surface significantly

### Attack Vectors

1. **Malicious Model on Hugging Face Hub**
   - Attacker uploads a model with malicious pickle payload
   - User downloads and loads the model
   - Code executes during deserialization

2. **Man-in-the-Middle (MITM) Attack**
   - Attacker intercepts model download
   - Replaces legitimate model with malicious version
   - User loads compromised model

3. **Local Cache Poisoning**
   - Attacker gains local file system access
   - Replaces cached model files
   - Application loads poisoned cache

4. **Data Processing Pipeline Exploitation**
   - Malicious data files in processing pipeline
   - Pickle-based cache files replaced with malicious versions

### Test Files

#### `test_cve_001_insecure_deserialization.py`

Main test suite covering:
- Pickle.load vulnerabilities in production code
- torch.load with weights_only=False patterns
- AST-based vulnerability detection
- Hugging Face Hub integration security
- Comprehensive documentation of affected components

Key test classes:
- `TestInsecurePickleDeserialization`: Tests for pickle.load vulnerabilities
- `TestInsecureTorchLoadDeserialization`: Tests for torch.load vulnerabilities
- `TestDeserializationCodePatterns`: AST-based analysis
- `TestHuggingFaceHubIntegration`: External model loading security
- `TestVulnerabilityDocumentation`: Documentation and classification

#### `test_cve_001_edge_cases.py`

Advanced exploitation scenarios:
- Pickle exploitation techniques (`__reduce__` method)
- PyTorch loading internals
- Real-world attack scenarios
- Mitigation bypasses
- Vulnerability chaining

Key test classes:
- `TestPickleExploitationVectors`: Pickle exploitation techniques
- `TestTorchLoadExploitationVectors`: PyTorch-specific exploits
- `TestRealWorldExploitScenarios`: Practical attack scenarios
- `TestDataProcessingVulnerabilities`: Data pipeline exploits
- `TestMitigationBypass`: Tests for incomplete mitigations
- `TestVulnerabilityChaining`: Multi-step attack chains

### Running the Tests

Run all security tests:
```bash
pytest tests/security/
```

Run specific test file:
```bash
pytest tests/security/test_cve_001_insecure_deserialization.py
```

Run with verbose output:
```bash
pytest tests/security/ -v
```

Run specific test class:
```bash
pytest tests/security/test_cve_001_insecure_deserialization.py::TestInsecurePickleDeserialization
```

Run specific test:
```bash
pytest tests/security/test_cve_001_insecure_deserialization.py::TestInsecurePickleDeserialization::test_data_explorer_pickle_load_vulnerability
```

### Affected Components

The following components are affected by CVE-001:

| Component | File Path | Vulnerability |
|-----------|-----------|---------------|
| Save/Restore Connector | `nemo/core/connectors/save_restore_connector.py:760` | `torch.load(weights_only=False)` |
| Data Explorer | `tools/speech_data_explorer/data_explorer.py:190` | `pickle.load(f)` |
| Adapter Mixins | `nemo/core/classes/mixins/adapter_mixins.py:962` | `torch.load(weights_only=False)` |
| Speech LLM Adapter | `nemo/collections/multimodal/speech_llm/parts/mixins/adapter_mixin.py:65` | `torch.load(weights_only=False)` |
| Modular Models | `nemo/collections/multimodal/speech_llm/models/modular_models.py:1089,1108` | `torch.load(weights_only=False)` |
| Hyena Model | `nemo/collections/llm/gpt/model/hyena.py:814,873` | `torch.load(weights_only=False)` |
| Model Checkpoint | `nemo/utils/callbacks/nemo_model_checkpoint.py:240` | `torch.load(weights_only=False)` |
| Megatron Strategy | `nemo/lightning/pytorch/strategies/megatron_strategy.py:1113` | `torch.load(weights_only=False)` |
| EMA Callbacks | `nemo/collections/common/callbacks/ema.py:138` | `torch.load(weights_only=False)` |
| TTS Dataset | `nemo/collections/tts/data/dataset.py` | `pickle.load()` |

### Expected Test Results

**IMPORTANT:** These tests are designed to **DETECT** the vulnerability, not fix it. All tests should **PASS**, indicating that the vulnerability is present. If tests fail, it may indicate that the vulnerability has been mitigated.

Expected behavior:
- ✅ Tests PASS = Vulnerability confirmed (needs fixing)
- ❌ Tests FAIL = Vulnerability may be mitigated (verify manually)

### Remediation Recommendations

To fix CVE-001, the following changes are recommended:

1. **Replace pickle with safer alternatives:**
   - Use JSON for simple data structures
   - Use Protocol Buffers for complex structured data
   - Use custom serialization with validation

2. **Update torch.load calls:**
   ```python
   # Vulnerable
   torch.load(path, weights_only=False)
   
   # Secure
   torch.load(path, weights_only=True)
   ```

3. **Implement model verification:**
   - Add cryptographic signature verification
   - Verify model integrity before loading
   - Use HMAC or digital signatures

4. **Add validation layers:**
   - Validate all deserialized data
   - Implement allowlists for expected data structures
   - Add runtime checks for suspicious patterns

5. **Secure Hugging Face Hub integration:**
   - Verify model signatures
   - Use trusted model repositories only
   - Implement model scanning before loading

### References

- [Pickle Security Documentation](https://docs.python.org/3/library/pickle.html#module-pickle)
- [PyTorch Security Best Practices](https://pytorch.org/docs/stable/notes/serialization.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

### Contributing

When adding new security tests:

1. Follow the existing test structure
2. Include detailed docstrings explaining the security risk
3. Add comments documenting vulnerability locations
4. Update this README with new findings
5. Ensure tests are designed to DETECT, not FIX vulnerabilities

### Security Disclosure

For security concerns or questions about these tests, please refer to the main NeMo security policy.

---

**Last Updated:** 2025-10-21  
**CVE Status:** Identified, awaiting remediation
