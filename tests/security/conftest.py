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
Security test configuration.

This conftest overrides the parent conftest to avoid loading heavy NeMo dependencies
for security tests that are primarily static analysis.
"""

import pytest


# Override fixtures from parent conftest that we don't need
@pytest.fixture(autouse=True)
def cleanup_local_folder():
    """Minimal cleanup fixture for security tests."""
    yield


@pytest.fixture(autouse=True)
def reset_singletons():
    """Minimal singleton reset for security tests."""
    yield


@pytest.fixture(autouse=True)
def reset_env_vars():
    """Minimal env var reset for security tests."""
    yield
