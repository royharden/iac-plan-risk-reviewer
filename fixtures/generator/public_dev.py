"""RV2 policy-derived PUBLIC DEVELOPMENT cases. Never a sealed acceptance oracle.

Expectations below were transcribed from Plan_M4_Selected_v1, not detector output.
Illustrative producer strings do not establish Terraform/provider compatibility.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path


def cases():
    sg = {
        "type": "ingress",
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "cidr_blocks": ["0.0.0.0/0"],
        "ipv6_cidr_blocks": [],
        "prefix_list_ids": [],
        "source_security_group_id": None,
        "self": False,
    }
    db = {"publicly_accessible": False, "storage_encrypted": True}
    rows = []

    def add(
        name,
        rule,
        outcome,
        resource_type,
        actions,
        before,
        after,
        *,
        applicability="supported",
        masks=None,
    ):
        change = {
            "actions": actions,
            "before": before,
            "after": after,
            "before_sensitive": {},
            "after_sensitive": {},
            "after_unknown": {},
        }
        change.update(masks or {})
        rows.append(
            (
                name,
                {
                    "format_version": "1.2",
                    "terraform_version": "1.9.0",
                    "complete": True,
                    "errored": False,
                    "resource_changes": [
                        {
                            "address": f'{resource_type}.rv2_public["ADDRESS_CANARY_RV2"]',
                            "name": "rv2_public",
                            "type": resource_type,
                            "mode": "managed",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "change": change,
                        }
                    ],
                },
                {"rule_id": rule, "applicability": applicability, "outcome": outcome},
            )
        )

    def r1(name, outcome, before, after, actions=None, **kwargs):
        add(
            name,
            "R1",
            outcome,
            "aws_security_group_rule",
            actions or ["update"],
            before,
            after,
            **kwargs,
        )

    r1("r1-world-ssh-create", "introduced_risk", None, sg, ["create"])
    r1(
        "r1-https-outside-policy",
        "clear",
        None,
        sg | {"from_port": 443, "to_port": 443},
        ["create"],
    )
    r1(
        "r1-ipv6-rdp",
        "introduced_risk",
        None,
        sg | {"from_port": 3389, "to_port": 3389, "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]},
        ["create"],
    )
    r1(
        "r1-cidr-reorder",
        "unchanged_risk",
        sg | {"cidr_blocks": ["0.0.0.0/0", "10.0.0.0/8"]},
        sg | {"cidr_blocks": ["10.0.0.0/8", "0.0.0.0/0"]},
    )
    r1("r1-add-rdp-to-ssh", "introduced_risk", sg, sg | {"to_port": 3389})
    r1("r1-unknown-prior", "indeterminate", {}, sg)
    add(
        "r1-inline-unsupported",
        "R1",
        None,
        "aws_security_group",
        ["create"],
        None,
        {},
        applicability="unsupported_shape",
    )

    add(
        "r2-public-create",
        "R2",
        "introduced_risk",
        "aws_db_instance",
        ["create"],
        None,
        db | {"publicly_accessible": True},
    )
    add(
        "r2-still-public",
        "R2",
        "unchanged_risk",
        "aws_db_instance",
        ["update"],
        db | {"publicly_accessible": True},
        db | {"publicly_accessible": True},
    )
    add(
        "r2-becomes-private",
        "R2",
        "clear",
        "aws_db_instance",
        ["update"],
        db | {"publicly_accessible": True},
        db,
    )
    add(
        "r2-unknown-prior",
        "R2",
        "indeterminate",
        "aws_db_instance",
        ["update"],
        {"storage_encrypted": True},
        db | {"publicly_accessible": True},
    )
    add(
        "r2-sensitive-after",
        "R2",
        "indeterminate",
        "aws_db_instance",
        ["update"],
        db,
        db | {"publicly_accessible": True},
        masks={"after_sensitive": {"publicly_accessible": True}},
    )

    add(
        "r3-removes-encryption",
        "R3",
        "introduced_risk",
        "aws_ebs_volume",
        ["update"],
        {"encrypted": True},
        {"encrypted": False},
    )
    add(
        "r3-create-unencrypted",
        "R3",
        "clear",
        "aws_ebs_volume",
        ["create"],
        None,
        {"encrypted": False},
    )
    add(
        "r3-unknown-prior",
        "R3",
        "indeterminate",
        "aws_ebs_volume",
        ["update"],
        {},
        {"encrypted": False},
    )
    add(
        "r3-still-encrypted",
        "R3",
        "clear",
        "aws_ebs_volume",
        ["update"],
        {"encrypted": True},
        {"encrypted": True},
    )
    add(
        "r3-missing-after",
        "R3",
        "indeterminate",
        "aws_ebs_volume",
        ["update"],
        {"encrypted": True},
        {},
    )

    for name, actions in (
        ("delete", ["delete"]),
        ("destroy-create", ["delete", "create"]),
        ("create-destroy", ["create", "delete"]),
    ):
        add(
            f"r4-{name}",
            "R4",
            "introduced_risk",
            "aws_ebs_volume",
            actions,
            {"encrypted": True, "tags": {"disposable": "yes"}},
            None if actions == ["delete"] else {"encrypted": True},
        )
    add("r4-create", "R4", "clear", "aws_ebs_volume", ["create"], None, {"encrypted": True})
    add(
        "r4-update",
        "R4",
        "clear",
        "aws_ebs_volume",
        ["update"],
        {"encrypted": True},
        {"encrypted": True},
    )
    add("r4-contradictory-prior", "R4", "indeterminate", "aws_ebs_volume", ["delete"], None, None)
    add(
        "r4-other-stateful",
        "R4",
        None,
        "aws_dynamodb_table",
        ["delete"],
        {},
        None,
        applicability="unsupported_shape",
    )
    return deepcopy(rows)


def generate(root: Path):
    inventory = []
    for case_id, plan, expected in cases():
        # No line terminators: Git autocrlf cannot change the raw-byte digest.
        raw = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
        path = root / "fixtures/scenarios/dev" / f"{case_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.read_bytes() != raw:
                raise ValueError(f"immutable public fixture differs: {case_id}")
        else:
            with path.open("xb") as stream:
                stream.write(raw)
        inventory.append(
            dict(
                case_id=case_id,
                path=path.relative_to(root).as_posix(),
                sha256=hashlib.sha256(raw).hexdigest(),
                split="dev",
                **expected,
            )
        )
    value = {
        "schema_version": 1,
        "split": "dev",
        "purpose": "public-development-only",
        "expectation_author": "M4-RV2 / 0024",
        "source": "Plan_M4_Selected_v1.md frozen truth boundaries",
        "independent_hidden_oracle": False,
        "producer_compatibility_tested": False,
        "cases": inventory,
    }
    path = root / "fixtures/expected/dev/rv2-policy-v1.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError("immutable public inventory differs")
    else:
        with path.open("xb") as stream:
            stream.write(raw)


if __name__ == "__main__":
    generate(Path(__file__).resolve().parents[2])
