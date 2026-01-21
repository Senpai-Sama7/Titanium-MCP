"""Unit tests for policy engine behavior."""

from titanium_repo_operator.policy import PolicyDecision, PolicyEngine


def test_dockerfile_requires_approval() -> None:
    policy = PolicyEngine()
    patch_text = "\n".join(
        [
            "diff --git a/Dockerfile b/Dockerfile",
            "index 1234567..89abcde 100644",
            "--- a/Dockerfile",
            "+++ b/Dockerfile",
            "@@ -1 +1 @@",
            "-FROM python:3.12",
            "+FROM python:3.12-slim",
        ]
    )
    result = policy.evaluate_patch(patch_text, ["Dockerfile"])

    assert result.decision == PolicyDecision.REQUIRE_APPROVAL
    assert result.requires_approval is True
