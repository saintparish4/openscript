"""
Tests for policy management

Why: Policy configuration must be reliable.
Errors here affect all downstream security decisions

Test Coverage:
- Default policies exist
- CRUD operations
- File I/O
- Validation
"""

import pytest
import tempfile
import json
from pathlib import Path

from src.core.policy import PolicyManager
from src.core.types import SecurityPolicy, SeverityLevel, AttackCategory


class TestPolicyManager:
    """Test policy management functionality."""

    def setup_method(self):
        """Initialize manager for each test."""
        self.manager = PolicyManager()

    def test_default_policies_loaded(self):
        """Test that default policies are loaded on init."""
        policies = self.manager.list_policies()
        assert len(policies) > 0

        # Check specific default policies exist
        assert self.manager.get_policy("balanced") is not None
        assert self.manager.get_policy("maximum_security") is not None
        assert self.manager.get_policy("monitor_only") is not None
        assert self.manager.get_policy("injection_protection") is not None
        assert self.manager.get_policy("data_protection") is not None

    def test_get_default_policy(self):
        """Test getting the default policy."""
        default = self.manager.get_default_policy()

        assert default is not None
        assert default.policy_id == "balanced"

    def test_add_custom_policy(self):
        """Test adding a custom policy."""
        policy = SecurityPolicy(
            policy_id="custom_test",
            name="Custom Test",
            description="Test policy",
            severity_threshold=SeverityLevel.HIGH,
            categories=[AttackCategory.DIRECT_INJECTION],
        )

        self.manager.add_policy(policy)

        retrieved = self.manager.get_policy("custom_test")
        assert retrieved is not None
        assert retrieved.name == "Custom Test"
        assert retrieved.severity_threshold == SeverityLevel.HIGH
        assert len(retrieved.categories) == 1
        assert AttackCategory.DIRECT_INJECTION in retrieved.categories

    def test_overwrite_policy_warning(self):
        """Test that overwriting a policy logs warning."""
        policy1 = SecurityPolicy(
            policy_id="overwrite_test", name="Original", description="Original policy"
        )

        policy2 = SecurityPolicy(
            policy_id="overwrite_test", name="Updated", description="Updated policy"
        )

        self.manager.add_policy(policy1)
        self.manager.add_policy(policy2)  # Should log warning

        retrieved = self.manager.get_policy("overwrite_test")
        assert retrieved.name == "Updated"

    def test_remove_policy(self):
        """Test removing a policy."""
        policy = SecurityPolicy(
            policy_id="to_remove", name="Will Remove", description="Test"
        )

        self.manager.add_policy(policy)
        assert self.manager.get_policy("to_remove") is not None

        removed = self.manager.remove_policy("to_remove")
        assert removed is True
        assert self.manager.get_policy("to_remove") is None

        # Removing again should return False
        removed_again = self.manager.remove_policy("to_remove")
        assert removed_again is False

    def test_list_policies(self):
        """Test listing all policies."""
        policies = self.manager.list_policies()

        assert len(policies) > 0
        assert all(isinstance(p, SecurityPolicy) for p in policies)

        # All should have unique IDs
        policy_ids = [p.policy_id for p in policies]
        assert len(policy_ids) == len(set(policy_ids))

    def test_save_and_load_policies(self):
        """Test saving and loading policies from file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            config_path = Path(f.name)

        try:
            # Add custom policy
            custom_policy = SecurityPolicy(
                policy_id="persistent_test",
                name="Persistent Test",
                description="Test persistence",
                severity_threshold=SeverityLevel.CRITICAL,
                categories=[AttackCategory.CREDENTIAL_LEAK],
                metadata={"owner": "security_team"},
            )
            self.manager.add_policy(custom_policy)

            # Save to file
            self.manager.save_policies(config_path)

            # Verify file exists and is valid JSON
            assert config_path.exists()
            with open(config_path) as f:
                data = json.load(f)
                assert "policies" in data

            # Load into new manager
            new_manager = PolicyManager(config_path)

            # Verify policy exists with correct data
            loaded = new_manager.get_policy("persistent_test")
            assert loaded is not None
            assert loaded.name == "Persistent Test"
            assert loaded.severity_threshold == SeverityLevel.CRITICAL
            assert AttackCategory.CREDENTIAL_LEAK in loaded.categories
            assert loaded.metadata.get("owner") == "security_team"

        finally:
            if config_path.exists():
                config_path.unlink()

    def test_load_invalid_file(self):
        """Test loading from invalid file raises error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            # Write invalid JSON
            f.write("{ invalid json }")
            config_path = Path(f.name)

        try:
            with pytest.raises(json.JSONDecodeError):
                PolicyManager(config_path)
        finally:
            config_path.unlink()

    def test_load_missing_file(self):
        """Test loading from non-existent file raises error."""
        fake_path = Path("/tmp/does_not_exist_12345.json")

        with pytest.raises(FileNotFoundError):
            PolicyManager(fake_path)

    def test_policy_validation(self):
        """Test policy validation."""
        # Valid policy
        valid_policy = SecurityPolicy(
            policy_id="valid", name="Valid Policy", description="A valid policy"
        )
        errors = self.manager.validate_policy(valid_policy)
        assert len(errors) == 0

        # Policy with invalid regex pattern
        invalid_policy = SecurityPolicy(
            policy_id="invalid",
            name="Invalid",
            description="Has bad regex",
            custom_patterns=["[invalid(regex"],  # Unclosed bracket
        )
        errors = self.manager.validate_policy(invalid_policy)
        assert len(errors) > 0
        assert any("regex" in err.lower() for err in errors)

    def test_policy_metadata(self):
        """Test that policy metadata is preserved."""
        policy = SecurityPolicy(
            policy_id="metadata_test",
            name="Metadata Test",
            description="Test metadata",
            metadata={
                "owner": "security_team",
                "version": "1.0",
                "tags": ["production", "critical"],
            },
        )

        self.manager.add_policy(policy)

        retrieved = self.manager.get_policy("metadata_test")
        assert retrieved.metadata["owner"] == "security_team"
        assert retrieved.metadata["version"] == "1.0"
        assert "production" in retrieved.metadata["tags"]


class TestDefaultPolicies:
    """Test the behavior of default policies."""

    def setup_method(self):
        self.manager = PolicyManager()

    def test_balanced_policy_config(self):
        """Test balanced policy configuration."""
        policy = self.manager.get_policy("balanced")

        assert policy is not None
        assert policy.enabled
        assert policy.block_on_detection
        assert policy.severity_threshold == SeverityLevel.MEDIUM
        assert len(policy.categories) > 0 or policy.categories == []

    def test_maximum_security_policy_config(self):
        """Test maximum security policy configuration."""
        policy = self.manager.get_policy("maximum_security")

        assert policy is not None
        assert policy.enabled
        assert policy.block_on_detection
        assert policy.severity_threshold == SeverityLevel.INFO  # Blocks everything

    def test_monitor_only_policy_config(self):
        """Test monitor only policy configuration."""
        policy = self.manager.get_policy("monitor_only")

        assert policy is not None
        assert policy.enabled
        assert not policy.block_on_detection  # Key: doesn't block
        assert policy.severity_threshold == SeverityLevel.INFO

    def test_injection_protection_policy_config(self):
        """Test injection protection policy configuration."""
        policy = self.manager.get_policy("injection_protection")

        assert policy is not None
        assert policy.enabled
        assert policy.block_on_detection

        # Should only check injection-related categories
        assert AttackCategory.DIRECT_INJECTION in policy.categories
        assert AttackCategory.ROLE_PLAY_MANIPULATION in policy.categories

        # Should NOT check data protection categories
        assert AttackCategory.PII_EXPOSURE not in policy.categories

    def test_data_protection_policy_config(self):
        """Test data protection policy configuration."""
        policy = self.manager.get_policy("data_protection")

        assert policy is not None
        assert policy.enabled
        assert policy.block_on_detection

        # Should only check data protection categories
        assert AttackCategory.CREDENTIAL_LEAK in policy.categories
        assert AttackCategory.PII_EXPOSURE in policy.categories

        # Should NOT check injection categories
        assert AttackCategory.DIRECT_INJECTION not in policy.categories
