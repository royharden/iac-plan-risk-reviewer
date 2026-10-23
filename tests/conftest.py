"""Small public-policy development builders, never hidden oracle material.

Dirty Mode authors these fixtures as source only; importing/running is deferred.
"""
from copy import deepcopy
import json

import pytest


@pytest.fixture
def core_change():
    def build(resource_type="aws_db_instance", *, actions=("update",), before=None,
              after=None, change_fields=None, **resource_fields):
        change = {"actions": list(actions), "before": deepcopy(before), "after": deepcopy(after)}
        change.update(deepcopy(change_fields or {}))
        entry = {
            "address": f"{resource_type}.synthetic", "name": "synthetic",
            "mode": "managed", "provider_name": "registry.terraform.io/hashicorp/aws",
            "type": resource_type, "change": change,
        }
        entry.update(resource_fields)
        return entry
    return build


@pytest.fixture
def core_plan_file(tmp_path):
    sequence = 0

    def write(changes=(), *, omit=(), **metadata):
        nonlocal sequence
        sequence += 1
        raw = {
            "format_version": "1.2", "terraform_version": "1.9.0",
            "complete": True, "errored": False, "resource_changes": list(changes),
        }
        raw.update(metadata)
        for key in omit:
            raw.pop(key, None)
        path = tmp_path / f"synthetic-plan-{sequence}.json"
        path.write_text(json.dumps(raw, allow_nan=False), encoding="utf-8")
        return path
    return write
