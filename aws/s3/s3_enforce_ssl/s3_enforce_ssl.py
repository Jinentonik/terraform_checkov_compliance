# checkov_custom/aws/s3_enforce_ssl.py
import json
from typing import Any, Dict, List, Union

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class S3EnforceSSL(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Ensure S3 buckets enforce SSL requests via bucket policy",
            id="CKV_AWS_998",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_s3_bucket_policy"],
        )

    def scan_resource_conf(self, conf: Dict[str, Any]) -> CheckResult:
        """
        Passes only if the bucket policy contains a Deny statement with
        Condition.Bool (or BoolIfExists) of {"aws:SecureTransport": false}.
        """
        policy_attr = conf.get("policy")
        if not policy_attr or not isinstance(policy_attr, list) or not policy_attr[0]:
            return CheckResult.FAILED

        raw_policy = policy_attr[0]
        try:
            policy = json.loads(raw_policy)
        except Exception:
            return CheckResult.FAILED

        statements: Union[List[Dict[str, Any]], Dict[str, Any]] = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            effect = stmt.get("Effect")
            if effect != "Deny":
                continue

            condition = stmt.get("Condition", {})
            # Accept either Bool or BoolIfExists operators
            for op in ("Bool", "BoolIfExists"):
                cond_map = condition.get(op, {})
                if isinstance(cond_map, dict) and "aws:SecureTransport" in cond_map:
                    val = cond_map.get("aws:SecureTransport")
                    # Allow boolean true/false or string "true"/"false"
                    is_false = (isinstance(val, bool) and val is False) or (
                        isinstance(val, str) and val.lower() == "false"
                    )
                    if is_false:
                        return CheckResult.PASSED

        return CheckResult.FAILED


check = S3EnforceSSL()
