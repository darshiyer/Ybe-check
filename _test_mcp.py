"""Quick end-to-end test for all 7 MCP tools + 3 prompt templates."""

import json
import time
import sys
import os

# Ensure proper imports
sys.path.insert(0, os.path.dirname(__file__))

from src.ybe_check.mcp_server import (
    mcp,
    scan_repo,
    list_findings,
    get_remediation,
    get_security_context,
    enhance_prompt,
    get_fix_prompt,
    get_review_prompt,
)

REPO = "/Users/adityaray/Desktop/hackx"
TEST_REPO = "/Users/adityaray/Desktop/hackx/A2K2-test"

PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"


def test(name, fn):
    try:
        start = time.time()
        result = fn()
        elapsed = time.time() - start
        print(f"{PASS}  {name}  ({elapsed:.2f}s)")
        return result
    except Exception as e:
        print(f"{FAIL}  {name}  — {e}")
        return None


def main():
    print("=" * 60)
    print("  YBE CHECK MCP SERVER — FULL TEST SUITE")
    print("=" * 60)
    print()

    # ── Tool Registration ──
    print("── Tool & Prompt Registration ──")
    tools = mcp._tool_manager.list_tools()
    tool_names = [t.name for t in tools]
    expected_tools = [
        "ybe.scan_repo", "ybe.list_findings", "ybe.get_remediation",
        "ybe.get_security_context", "ybe.enhance_prompt",
        "ybe.get_fix_prompt", "ybe.get_review_prompt",
    ]
    for t in expected_tools:
        if t in tool_names:
            print(f"  {PASS}  Tool registered: {t}")
        else:
            print(f"  {FAIL}  Tool MISSING: {t}")

    prompts = mcp._prompt_manager.list_prompts()
    prompt_names = [p.name for p in prompts]
    for p in ["security-audit", "fix-critical", "review-file"]:
        if p in prompt_names:
            print(f"  {PASS}  Prompt registered: {p}")
        else:
            print(f"  {FAIL}  Prompt MISSING: {p}")

    print()
    print("── Tool 1: ybe.scan_repo (live scan, 2 modules) ──")

    def t1():
        r = scan_repo(path=TEST_REPO, modules=["secrets", "pii_logging"])
        d = json.loads(r)
        assert "overall_score" in d, "Missing overall_score"
        assert "findings" in d, "Missing findings"
        assert "verdict" in d, "Missing verdict"
        assert len(d["modules_run"]) == 2, f"Expected 2 modules, got {len(d['modules_run'])}"
        print(f"       Score: {d['overall_score']}/100 — {d['verdict']}")
        print(f"       Findings: {len(d['findings'])}, Modules: {d['modules_run']}")
        return d
    scan_result = test("scan_repo", t1)

    print()
    print("── Tool 2: ybe.list_findings (from cached report) ──")

    def t2():
        r = list_findings(path=REPO, severity="high")
        d = json.loads(r)
        assert isinstance(d, list), "Expected list"
        assert len(d) > 0, "Expected at least one high finding"
        print(f"       High findings: {len(d)}")
        print(f"       First: [{d[0]['id']}] {d[0]['summary'][:60]}")
        return d
    test("list_findings (severity=high)", t2)

    def t2b():
        r = list_findings(path=REPO, category="static")
        d = json.loads(r)
        assert isinstance(d, list), "Expected list"
        print(f"       Static findings: {len(d)}")
        return d
    test("list_findings (category=static)", t2b)

    print()
    print("── Tool 3: ybe.get_remediation ──")

    def t3():
        r = get_remediation(path=REPO, finding_id="secrets:0")
        d = json.loads(r)
        assert "finding_id" in d, "Missing finding_id"
        assert "remediation" in d, "Missing remediation"
        assert "impact" in d, "Missing impact"
        print(f"       Finding: {d['finding_id']}")
        print(f"       Impact: {d['impact'][:80]}...")
        return d
    test("get_remediation (secrets:0)", t3)

    def t3b():
        r = get_remediation(path=REPO, finding_id="nonexistent:99")
        d = json.loads(r)
        assert "error" in d, "Expected error for missing finding"
        print(f"       Correctly returned error: {d['error']}")
        return d
    test("get_remediation (invalid ID → error)", t3b)

    print()
    print("── Tool 4: ybe.get_security_context ──")

    def t4():
        r = get_security_context(path=REPO)
        d = json.loads(r)
        assert "overall_score" in d, "Missing overall_score"
        assert "severity_breakdown" in d, "Missing severity_breakdown"
        assert "top_findings" in d, "Missing top_findings"
        assert "weakest_modules" in d, "Missing weakest_modules"
        print(f"       Score: {d['overall_score']}/100 — {d['verdict']}")
        print(f"       Severity: {json.dumps(d['severity_breakdown'])}")
        return d
    test("get_security_context", t4)

    def t4b():
        r = get_security_context(path=REPO, file="app.py")
        d = json.loads(r)
        assert "file_filter" in d, "Missing file_filter"
        assert "file_findings" in d, "Missing file_findings"
        print(f"       File findings for app.py: {len(d['file_findings'])}")
        return d
    test("get_security_context (file=app.py)", t4b)

    print()
    print("── Tool 5: ybe.enhance_prompt ──")

    def t5():
        r = enhance_prompt(
            path=REPO,
            user_prompt="Add user authentication to app.py",
            file="app.py",
        )
        d = json.loads(r)
        assert "enhanced_prompt" in d, "Missing enhanced_prompt"
        assert "context" in d, "Missing context"
        assert "Security Context" in d["enhanced_prompt"], "Missing security header"
        assert "User Request" in d["enhanced_prompt"], "Missing user request section"
        print(f"       Enhanced prompt length: {len(d['enhanced_prompt'])} chars")
        print(f"       Contains security context: Yes")
        print(f"       Contains user request: Yes")
        return d
    test("enhance_prompt", t5)

    print()
    print("── Tool 6: ybe.get_fix_prompt ──")

    def t6():
        r = get_fix_prompt(path=REPO, finding_id="secrets:0")
        d = json.loads(r)
        assert "prompt" in d, "Missing prompt"
        assert "finding_id" in d, "Missing finding_id"
        assert "Fix this" in d["prompt"], "Prompt doesn't start correctly"
        print(f"       Prompt length: {len(d['prompt'])} chars")
        print(f"       First line: {d['prompt'].splitlines()[0]}")
        return d
    test("get_fix_prompt (secrets:0)", t6)

    def t6b():
        r = get_fix_prompt(path=REPO, finding_id="nonexistent:99")
        d = json.loads(r)
        assert "error" in d, "Expected error for missing finding"
        print(f"       Correctly returned error: {d['error']}")
        return d
    test("get_fix_prompt (invalid ID → error)", t6b)

    print()
    print("── Tool 7: ybe.get_review_prompt ──")

    def t7():
        r = get_review_prompt(path=REPO, file="A2K2-test/app.py")
        d = json.loads(r)
        assert "prompt" in d, "Missing prompt"
        assert "known_issues" in d, "Missing known_issues"
        assert "workspace_score" in d, "Missing workspace_score"
        assert d["known_issues"] > 0, "Expected known issues for app.py"
        print(f"       Known issues: {d['known_issues']}")
        print(f"       Workspace score: {d['workspace_score']}")
        return d
    test("get_review_prompt (A2K2-test/app.py)", t7)

    def t7b():
        r = get_review_prompt(path=REPO, file="nonexistent_file.py")
        d = json.loads(r)
        assert d["known_issues"] == 0, "Expected 0 issues for non-existent file"
        assert "No known findings" in d["prompt"], "Expected fallback prompt"
        print(f"       Correctly returned generic review prompt for unknown file")
        return d
    test("get_review_prompt (unknown file → fallback)", t7b)

    print()
    print("=" * 60)
    print("  ALL TESTS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
