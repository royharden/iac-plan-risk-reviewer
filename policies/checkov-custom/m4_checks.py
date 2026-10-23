"""Checkov external-policy entrypoint; requires a separately installed Checkov.

Not imported by product/evaluation source during Dirty Mode. These module-level
registrations follow Checkov's external-policy API and execute only after later
explicit scanner activation. Missing dependency is an import failure, never PASS.
"""
from __future__ import annotations

import os
from pathlib import Path

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

from m4_policy import TYPES, evaluate_change, load_resource


class M4ChangeCheck(BaseResourceCheck):
    def __init__(self, rule: str) -> None:
        self.m4_rule = rule
        super().__init__(name=f"M4 declared change predicate {rule}",
                         id=f"CKV_M4_{rule}",
                         categories=(CheckCategories.GENERAL_SECURITY,),
                         supported_resources=TYPES[rule])

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        self.evaluated_keys = ["__change_actions__"]
        # No raw plan values, addresses or paths are included in check names/reasons.
        try:
            address = conf.get("__address__")
            actions = conf.get("__change_actions__")
            if not isinstance(address, str) or not isinstance(actions, list):
                return CheckResult.UNKNOWN
            plan_path = os.environ.get("IAC_CUSTOM_PLAN_JSON")
            plan_hash = os.environ.get("IAC_CUSTOM_PLAN_SHA256")
            if not plan_path or not plan_hash:
                return CheckResult.UNKNOWN
            resource = load_resource(Path(plan_path), plan_hash, address)
            if resource.get("change", {}).get("actions") != actions:
                return CheckResult.UNKNOWN
            decision = evaluate_change(resource, self.m4_rule)
            if (decision.applicability != "supported" or decision.coverage
                    or decision.outcome == "indeterminate"):
                return CheckResult.UNKNOWN
            # This is the introduced-risk comparison target. Unchanged risk is
            # a negative here, never a claim that its configuration is secure.
            return (CheckResult.FAILED if decision.outcome == "introduced_risk"
                    else CheckResult.PASSED)
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            return CheckResult.UNKNOWN


check_r1 = M4ChangeCheck("R1")
check_r2 = M4ChangeCheck("R2")
check_r3 = M4ChangeCheck("R3")
check_r4 = M4ChangeCheck("R4")
