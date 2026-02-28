"""
Unified findings schema for all Ybe Check modules.
Each finding conforms to this structure for consistent reporting and MCP tooling.
"""

from typing import Any, Optional

# Severity levels (ordered for filtering)
SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")

# Category for module grouping
CATEGORY_STATIC = "static"
CATEGORY_DYNAMIC = "dynamic"
CATEGORY_INFRA = "infra"


def make_finding(
    *,
    id: str,
    source: str,
    category: str,
    type: str,
    severity: str,
    location: dict[str, Any],
    summary: str,
    details: Optional[str] = None,
    evidence: Optional[dict] = None,
    linked_static_id: Optional[str] = None,
    ai_analysis: Optional[dict] = None,
    metadata: Optional[dict] = None,
) -> dict[str, Any]:
    """Build a finding dict conforming to the unified schema."""
    return {
        "id": id,
        "source": source,
        "category": category,
        "type": type,
        "severity": severity,
        "location": {
            "path": location.get("path"),
            "line": location.get("line"),
            "endpoint": location.get("endpoint"),
            "resource": location.get("resource"),
        },
        "summary": summary,
        "details": details,
        "evidence": evidence,
        "linked_static_id": linked_static_id,
        "ai_analysis": ai_analysis,
        "metadata": metadata,
    }


def detail_to_finding(
    detail: dict,
    source: str,
    category: str,
    finding_idx: int,
) -> dict[str, Any]:
    """
    Adapt a module's detail dict (file, line, type, severity, reason) into
    the unified finding schema. Keeps changes minimal — no module rewrites.
    """
    fid = f"{source}:{finding_idx}"
    loc = {
        "path": detail.get("file"),
        "line": detail.get("line"),
        "endpoint": detail.get("url") or detail.get("endpoint"),
        "resource": detail.get("resource") or detail.get("package"),
    }
    summary = detail.get("reason") or detail.get("type") or "Finding"
    return make_finding(
        id=fid,
        source=source,
        category=category,
        type=detail.get("type", "issue"),
        severity=detail.get("severity", "medium"),
        location=loc,
        summary=summary[:500],
        details=detail.get("description"),
        evidence={"snippet": detail.get("snippet"), "match": detail.get("match")}
        if detail.get("snippet") or detail.get("match")
        else None,
        metadata={
            k: v
            for k, v in detail.items()
            if k not in ("file", "line", "type", "severity", "reason", "description", "snippet", "match")
        },
    )
