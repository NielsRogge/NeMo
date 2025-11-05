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
Security Tests Package

This package contains security vulnerability tests for the NeMo framework.
These tests verify the presence of security vulnerabilities and do NOT
fix them - they serve as documentation and verification of security issues.

Test Organization:
- test_cve_008_arbitrary_file_write.py: Tests for CVE-008 arbitrary file write vulnerability

Running Security Tests:
    pytest tests/security/ -v
    pytest tests/security/ -m security
    pytest tests/security/ -m cve_008
"""
