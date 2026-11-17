
import json
import hashlib
import re
from pathlib import Path
from engine_t1537_candidate import Engine


class VerifiedEngine(Engine):
    def __init__(self, store, allowlist=None, baseline=None,
                 evidence_path=None):

        super().__init__(store, allowlist, baseline)

        # A fresh installation has no locally approved exceptions. Never copy
        # another site's normal-test evidence into a new site's decisions.
        evidence = (json.loads(Path(evidence_path).read_text(encoding="utf-8"))
                    if evidence_path else {"schema_version": 1, "approved_normal": []})

        if evidence.get("schema_version") != 1:
            raise ValueError("지원하지 않는 근거 파일 버전")

        self.verified_normal = {}

        for row in evidence.get("approved_normal", []):
            mid = row["message_id"]
            digest = row["sha256"]

            if row.get("classification") != "verified_normal_test":
                raise ValueError("승인되지 않은 판정 종류")

            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("잘못된 해시")

            if mid in self.verified_normal:
                raise ValueError("중복 메시지 ID")

            self.verified_normal[mid] = row

    def eval_rule(self, rule, event):
        if str(rule) == "kb:rule_image_send_cross_project":
            raw = event["raw"]

            if raw.get("event_type") == "image.send":
                mid = raw.get("message_id")
                record = self.verified_normal.get(mid)

                if record:
                    payload = raw.get("payload") or {}

                    encoded = json.dumps(
                        raw, ensure_ascii=False, sort_keys=True
                    ).encode("utf-8")

                    digest = hashlib.sha256(encoded).hexdigest()

                    if (
                        digest == record["sha256"]
                        and payload.get("image_id") == record["image_id"]
                        and raw.get("timestamp") == record["timestamp"]
                    ):
                        return None

        return super().eval_rule(rule, event)
