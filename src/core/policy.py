"""
Policy management and enforcement

Why: Enterprises need customizable policies.
Separate policy management from detection logic for flexibility

Design:
- Policies are data, not code
- Easy to create, modify, and version policies
- Policies can be loaded from files or database
- Audit trail for all policy changes
"""

from typing import Dict, List, Optional
import json
from pathlib import Path
import structlog

from .types import SecurityPolicy, SeverityLevel, AttackCategory

logger = structlog.get_logger()


class PolicyManager:
    """
    Manages security policies

    Responsibilities:
    - Store and retrieve policies
    - Load/save policies from/to files
    - Provide default policies
    - Validate policy consistency

    Thread Safety: Methods are thread-safe for reading
    Modifications should be serialized
    """

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize policy manager

        Args:
            config_path: Optional path to policy configuration file
        """
        self.policies: Dict[str, SecurityPolicy] = {}
        self.logger = logger.bind(component="policy_manager")

        if config_path:
            self.load_policies(config_path)
        else:
            self._load_default_policies()

    def _load_default_policies(self):
        """
        Load default built-in policies

        These policies cover common use cases:
        - Maximum security (production)
        - Balanced (default)
        - Monitoring only (dev/test)
        - Focused policies (injection, data protection)
        """

        # Maximum security - block everything
        self.add_policy(
            SecurityPolicy(
                policy_id="maximum_security",
                name="Maximum Security",
                description=(
                    "Block all detected threats regardless of severity. "
                    "Use for production environments requiring highest protection."
                ),
                enabled=True,
                block_on_detection=True,
                severity_threshold=SeverityLevel.INFO,
                categories=list(AttackCategory),
                metadata={"use_case": "production", "compliance": ["SOC2", "HIPAA"]},
            )
        )

        # Balanced - block medium and above (DEFAULT)
        self.add_policy(
            SecurityPolicy(
                policy_id="balanced",
                name="Balanced Security",
                description=(
                    "Block medium severity and above. "
                    "Good balance between security and false positives. "
                    "Recommended for most applications."
                ),
                enabled=True,
                block_on_detection=True,
                severity_threshold=SeverityLevel.MEDIUM,
                categories=list(AttackCategory),
                metadata={"use_case": "general", "default": True},
            )
        )

        # Monitoring only - log everything, block nothing
        self.add_policy(
            SecurityPolicy(
                policy_id="monitor_only",
                name="Monitor Only",
                description=(
                    "Detect and log threats without blocking. "
                    "Use for testing, tuning false positives, or audit mode."
                ),
                enabled=True,
                block_on_detection=False,
                severity_threshold=SeverityLevel.INFO,
                categories=list(AttackCategory),
                metadata={"use_case": "testing", "blocking": False},
            )
        )

        # Injection focus - only prompt injection attacks
        self.add_policy(
            SecurityPolicy(
                policy_id="injection_protection",
                name="Injection Protection",
                description=(
                    "Focus on prompt injection attacks. "
                    "Block direct injection, role manipulation, and context poisoning. "
                    "Use when main concern is prompt injection."
                ),
                enabled=True,
                block_on_detection=True,
                severity_threshold=SeverityLevel.MEDIUM,
                categories=[
                    AttackCategory.DIRECT_INJECTION,
                    AttackCategory.ROLE_PLAY_MANIPULATION,
                    AttackCategory.DELIMITER_CONFUSION,
                    AttackCategory.CONTEXT_POISONING,
                    AttackCategory.JAILBREAK,
                ],
                metadata={
                    "use_case": "injection_focus",
                    "threat_model": "prompt_injection",
                },
            )
        )

        # Data protection - focus on leaks and PII
        self.add_policy(
            SecurityPolicy(
                policy_id="data_protection",
                name="Data Protection",
                description=(
                    "Prevent data exfiltration and leaks. "
                    "Block credential leaks, PII exposure, and system prompt leaks. "
                    "Use for compliance-sensitive applications."
                ),
                enabled=True,
                block_on_detection=True,
                severity_threshold=SeverityLevel.HIGH,
                categories=[
                    AttackCategory.DATA_EXFILTRATION,
                    AttackCategory.CREDENTIAL_LEAK,
                    AttackCategory.PII_EXPOSURE,
                    AttackCategory.SYSTEM_PROMPT_LEAK,
                ],
                metadata={
                    "use_case": "data_protection",
                    "compliance": ["GDPR", "CCPA", "PCI-DSS"],
                    "threat_model": "data_leakage",
                },
            )
        )

        # Permissive - only block critical
        self.add_policy(
            SecurityPolicy(
                policy_id="permissive",
                name="Permissive",
                description=(
                    "Only block critical threats. "
                    "Minimal false positives, but some attacks may get through. "
                    "Use for low-risk applications or early testing."
                ),
                enabled=True,
                block_on_detection=True,
                severity_threshold=SeverityLevel.CRITICAL,
                categories=list(AttackCategory),
                metadata={"use_case": "low_risk", "false_positive_tolerance": "low"},
            )
        )

        self.logger.info("default_policies_loaded", count=len(self.policies))

    def add_policy(self, policy: SecurityPolicy) -> None:
        """
        Add or update a policy.

        Args:
            policy: SecurityPolicy to add

        Raises:
            ValueError: If policy is invalid
        """
        # Validate policy
        if not policy.policy_id:
            raise ValueError("Policy must have an ID")

        if not policy.name:
            raise ValueError("Policy must have a name")

        # Warn if overwriting
        if policy.policy_id in self.policies:
            self.logger.warning(
                "policy_overwrite",
                policy_id=policy.policy_id,
                old_name=self.policies[policy.policy_id].name,
                new_name=policy.name,
            )

        self.policies[policy.policy_id] = policy

        self.logger.info(
            "policy_added",
            policy_id=policy.policy_id,
            name=policy.name,
            severity_threshold=policy.severity_threshold.value,
            blocks=policy.block_on_detection,
            category_count=len(policy.categories) if policy.categories else "all",
        )

    def get_policy(self, policy_id: str) -> Optional[SecurityPolicy]:
        """
        Get a policy by ID.

        Args:
            policy_id: Policy identifier

        Returns:
            SecurityPolicy or None if not found
        """
        policy = self.policies.get(policy_id)

        if policy is None:
            self.logger.warning(
                "policy_not_found",
                policy_id=policy_id,
                available_policies=list(self.policies.keys()),
            )

        return policy

    def get_default_policy(self) -> SecurityPolicy:
        """
        Get the default policy.

        Returns:
            The 'balanced' policy by default
        """
        return self.get_policy("balanced") or list(self.policies.values())[0]

    def list_policies(self) -> List[SecurityPolicy]:
        """
        List all policies.

        Returns:
            List of all policies
        """
        return list(self.policies.values())

    def remove_policy(self, policy_id: str) -> bool:
        """
        Remove a policy.

        Args:
            policy_id: Policy to remove

        Returns:
            True if removed, False if not found
        """
        if policy_id in self.policies:
            policy = self.policies[policy_id]
            del self.policies[policy_id]

            self.logger.info("policy_removed", policy_id=policy_id, name=policy.name)
            return True

        return False

    def load_policies(self, config_path: Path) -> None:
        """
        Load policies from JSON file.

        File format:
        {
            "policies": [
                {
                    "policy_id": "custom",
                    "name": "Custom Policy",
                    ...
                }
            ]
        }

        Args:
            config_path: Path to JSON configuration file

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is invalid
        """
        try:
            with open(config_path, "r") as f:
                data = json.load(f)

            if "policies" not in data:
                raise ValueError("Config file must have 'policies' key")

            loaded_count = 0
            for policy_data in data["policies"]:
                # Convert string enums to actual enums
                if "severity_threshold" in policy_data:
                    policy_data["severity_threshold"] = SeverityLevel(
                        policy_data["severity_threshold"]
                    )

                if "categories" in policy_data:
                    policy_data["categories"] = [
                        AttackCategory(cat) for cat in policy_data["categories"]
                    ]

                policy = SecurityPolicy(**policy_data)
                self.add_policy(policy)
                loaded_count += 1

            self.logger.info(
                "policies_loaded_from_file",
                path=str(config_path),
                count=loaded_count,
                total_policies=len(self.policies),
            )

        except Exception as e:
            self.logger.error(
                "policy_load_failed",
                path=str(config_path),
                error=str(e),
                error_type=type(e).__name__,
            )
            raise

    def save_policies(self, config_path: Path) -> None:
        """
        Save policies to JSON file.

        Args:
            config_path: Path to save configuration

        Raises:
            IOError: If file cannot be written
        """
        try:
            policies_data = {
                "policies": [
                    {
                        "policy_id": p.policy_id,
                        "name": p.name,
                        "description": p.description,
                        "enabled": p.enabled,
                        "block_on_detection": p.block_on_detection,
                        "severity_threshold": p.severity_threshold.value,
                        "categories": [c.value for c in p.categories],
                        "custom_patterns": p.custom_patterns,
                        "metadata": p.metadata,
                    }
                    for p in self.policies.values()
                ]
            }

            # Create parent directory if it doesn't exist
            config_path.parent.mkdir(parents=True, exist_ok=True)

            with open(config_path, "w") as f:
                json.dump(policies_data, f, indent=2)

            self.logger.info(
                "policies_saved_to_file",
                path=str(config_path),
                count=len(self.policies),
            )

        except Exception as e:
            self.logger.error(
                "policy_save_failed",
                path=str(config_path),
                error=str(e),
                error_type=type(e).__name__,
            )
            raise

    def validate_policy(self, policy: SecurityPolicy) -> List[str]:
        """
        Validate a policy configuration.

        Args:
            policy: Policy to validate

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        if not policy.policy_id:
            errors.append("Policy ID is required")

        if not policy.name:
            errors.append("Policy name is required")

        # Check for conflicting settings
        if (
            not policy.block_on_detection
            and policy.severity_threshold == SeverityLevel.INFO
        ):
            errors.append(
                "Warning: Policy won't block but has INFO threshold. "
                "This will generate many alerts."
            )

        # Validate custom patterns
        if policy.custom_patterns:
            import re

            for i, pattern in enumerate(policy.custom_patterns):
                try:
                    re.compile(pattern)
                except re.error as e:
                    errors.append(f"Invalid regex pattern #{i}: {e}")

        return errors
