from agent.prompts import SYSTEM_PROMPT, build_result_explainer_prompt, build_skill_router_prompt


def test_system_prompt_emphasizes_evidence_and_safety():
    assert "Never claim a check was performed unless tool output exists." in SYSTEM_PROMPT
    assert "Do not suggest destructive" in SYSTEM_PROMPT


def test_build_skill_router_prompt_requires_json_only_for_actions():
    prompt = build_skill_router_prompt("check whether 192.168.1.10 is reachable")
    assert "respond with JSON only" in prompt
    assert '"skill": "check_device_connectivity"' in prompt
    assert "Do not wrap JSON in markdown fences." in prompt


def test_build_result_explainer_prompt_calls_out_unknowns_and_next_step():
    result = {"skill": "check_device_connectivity", "host": "192.168.1.10", "status": "unreachable"}
    prompt = build_result_explainer_prompt("check 192.168.1.10", result)
    assert "Separate confirmed findings from unknowns or limitations." in prompt
    assert "End with one safest useful next step." in prompt
    assert '"host": "192.168.1.10"' in prompt
