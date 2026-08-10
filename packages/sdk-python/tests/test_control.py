import pytest
import math

from apex_sdk.control import ControlAction, ControlCommand, ControlValidationError


def test_control_commands_are_cooperative_and_serializable() -> None:
    command = ControlCommand.create(ControlAction.PAUSE, reason_code="operator_requested")

    assert command.enforcement == "cooperative"
    assert command.to_event_data() == {
        "action": "pause",
        "enforcement": "cooperative",
        "reason_code": "operator_requested",
        "parameters": {},
    }


def test_inject_command_marks_supplied_text_as_untrusted_data() -> None:
    command = ControlCommand.create(ControlAction.INJECT, content="Use this observation")

    assert command.to_event_data()["parameters"] == {
        "content": "Use this observation",
        "content_classification": "untrusted",
    }


def test_budget_command_requires_budget_kind_and_positive_limit() -> None:
    command = ControlCommand.create(ControlAction.SET_BUDGET, budget_kind="tokens", limit=100)
    assert command.to_event_data()["parameters"] == {"budget_kind": "tokens", "limit": 100}

    with pytest.raises(ControlValidationError, match="budget_kind"):
        ControlCommand.create(ControlAction.SET_BUDGET, limit=100)
    with pytest.raises(ControlValidationError, match="positive"):
        ControlCommand.create(ControlAction.SET_BUDGET, budget_kind="tokens", limit=0)
    with pytest.raises(ControlValidationError, match="finite"):
        ControlCommand.create(ControlAction.SET_BUDGET, budget_kind="tokens", limit=math.inf)


def test_control_rejects_forced_enforcement_and_invalid_action_parameters() -> None:
    with pytest.raises(ControlValidationError, match="cooperative"):
        ControlCommand.create(ControlAction.STOP, enforcement="forced")
    with pytest.raises(ControlValidationError, match="content"):
        ControlCommand.create(ControlAction.INJECT)
    with pytest.raises(ControlValidationError, match="does not accept"):
        ControlCommand.create(ControlAction.RESUME, reason_code="not-allowed")


def test_inject_rejects_budget_parameters() -> None:
    with pytest.raises(ControlValidationError, match="budget parameters"):
        ControlCommand.create(ControlAction.INJECT, content="hello", limit=1)


def test_inject_rejects_oversized_untrusted_content() -> None:
    with pytest.raises(ControlValidationError, match="32 KiB"):
        ControlCommand.create(ControlAction.INJECT, content="x" * (32 * 1024 + 1))


def test_budget_rejects_content() -> None:
    with pytest.raises(ControlValidationError, match="does not accept content"):
        ControlCommand.create(ControlAction.SET_BUDGET, budget_kind="cost", limit=1, content="hello")


def test_control_command_rejects_runtime_invalid_actions_and_reason_codes() -> None:
    with pytest.raises(ControlValidationError, match="action"):
        ControlCommand.create("stop")  # type: ignore[arg-type]
    with pytest.raises(ControlValidationError, match="reason_code"):
        ControlCommand.create(ControlAction.PAUSE, reason_code="operator\nrequest")


def test_control_event_data_does_not_expose_mutable_command_parameters() -> None:
    command = ControlCommand.create(ControlAction.INJECT, content="untrusted text")
    event_data = command.to_event_data()
    event_data["parameters"]["content_classification"] = "trusted"

    assert command.to_event_data()["parameters"]["content_classification"] == "untrusted"


def test_stop_rejects_action_parameters() -> None:
    with pytest.raises(ControlValidationError, match="does not accept parameters"):
        ControlCommand.create(ControlAction.STOP, limit=1)


def test_resolve_hold_command_carries_the_matching_token_and_decision() -> None:
    command = ControlCommand.create(
        ControlAction.RESOLVE_HOLD,
        hold_token="018f0000-0000-7000-8000-000000000001",
        decision="approved",
        reason="looks legitimate",
    )
    assert command.to_event_data()["parameters"] == {
        "hold_token": "018f0000-0000-7000-8000-000000000001",
        "decision": "approved",
        "reason": "looks legitimate",
    }


def test_resolve_hold_reason_is_optional() -> None:
    command = ControlCommand.create(
        ControlAction.RESOLVE_HOLD, hold_token="hold-1", decision="denied"
    )
    assert command.to_event_data()["parameters"] == {
        "hold_token": "hold-1",
        "decision": "denied",
        "reason": None,
    }


def test_resolve_hold_requires_a_safe_identifier_hold_token() -> None:
    with pytest.raises(ControlValidationError, match="hold_token"):
        ControlCommand.create(ControlAction.RESOLVE_HOLD, decision="approved")
    with pytest.raises(ControlValidationError, match="hold_token"):
        ControlCommand.create(
            ControlAction.RESOLVE_HOLD, hold_token="not a safe identifier", decision="approved"
        )


def test_resolve_hold_requires_an_approved_or_denied_decision() -> None:
    with pytest.raises(ControlValidationError, match="approved or denied"):
        ControlCommand.create(ControlAction.RESOLVE_HOLD, hold_token="hold-1", decision="maybe")
    with pytest.raises(ControlValidationError, match="approved or denied"):
        ControlCommand.create(ControlAction.RESOLVE_HOLD, hold_token="hold-1")


def test_resolve_hold_rejects_an_oversized_reason() -> None:
    with pytest.raises(ControlValidationError, match="8 KiB"):
        ControlCommand.create(
            ControlAction.RESOLVE_HOLD,
            hold_token="hold-1",
            decision="denied",
            reason="x" * (8 * 1024 + 1),
        )


def test_resolve_hold_rejects_inject_and_budget_parameters() -> None:
    with pytest.raises(ControlValidationError, match="does not accept"):
        ControlCommand.create(
            ControlAction.RESOLVE_HOLD, hold_token="hold-1", decision="approved", content="hello"
        )
    with pytest.raises(ControlValidationError, match="does not accept"):
        ControlCommand.create(
            ControlAction.RESOLVE_HOLD, hold_token="hold-1", decision="approved", limit=1
        )


def test_inject_and_set_budget_reject_resolve_hold_parameters() -> None:
    with pytest.raises(ControlValidationError, match="budget parameters"):
        ControlCommand.create(ControlAction.INJECT, content="hello", decision="approved")
    with pytest.raises(ControlValidationError, match="does not accept content"):
        ControlCommand.create(
            ControlAction.SET_BUDGET, budget_kind="cost", limit=1, hold_token="hold-1"
        )
