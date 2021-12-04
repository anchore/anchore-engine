import pytest

from anchore_engine.subsys.taskstate import (
    state_graphs,
    init_state,
    reset_state,
    base_state,
    fault_state,
    queued_state,
    working_state,
    next_state,
    complete_state,
    orphaned_state,
)


@pytest.mark.parametrize(
    "param",
    [
        pytest.param(
            {
                "state_type": "analyze",
                "current_state": None,
                "reset": False,
                "expected": state_graphs["analyze"]["base_state"],
            },
            id="basic-no-current-state",
        ),
        pytest.param(
            {
                "state_type": "analyze",
                "current_state": "somerandomstate",
                "reset": False,
                "expected": "somerandomstate",
            },
            id="basic-with-current-state",
        ),
        pytest.param(
            {
                "state_type": "analyze",
                "current_state": "somerandomstate",
                "reset": True,
                "expected": state_graphs["analyze"]["base_state"],
            },
            id="basic-reset",
        ),
    ],
)
def test_init_state(param):
    actual_state = init_state(
        param["state_type"], param["current_state"], param["reset"]
    )
    assert actual_state == param["expected"]


@pytest.mark.parametrize(
    "state_type",
    [
        "analyze",
        "policy_evaluate",
        "image_status",
        "service_status",
        "policy_engine_state",
    ],
)
def test_reset_state(state_type):
    assert reset_state(state_type) == state_graphs[state_type]["base_state"]


@pytest.mark.parametrize(
    "state_type",
    [
        "analyze",
        "policy_evaluate",
        "image_status",
        "service_status",
        "policy_engine_state",
    ],
)
def test_base_state(state_type):
    assert base_state(state_type) == state_graphs[state_type]["base_state"]


@pytest.mark.parametrize(
    "state_type",
    [
        "analyze",
        "policy_evaluate",
        "image_status",
        "service_status",
        "policy_engine_state",
    ],
)
def test_fault_state(state_type):
    assert fault_state(state_type) == state_graphs[state_type]["fault_state"]


@pytest.mark.parametrize(
    "state_type",
    [
        "analyze",
        "policy_evaluate",
        "image_status",
        "service_status",
        "policy_engine_state",
    ],
)
def test_queued_state(state_type):
    assert queued_state(state_type) == state_graphs[state_type]["queued_state"]


@pytest.mark.parametrize(
    "state_type",
    [
        "analyze",
        "policy_evaluate",
        "image_status",
        "service_status",
        "policy_engine_state",
    ],
)
def test_working_state(state_type):
    assert working_state(state_type) == state_graphs[state_type]["working_state"]


@pytest.mark.parametrize(
    "state_type,current",
    [
        ("analyze", ""),
        ("analyze", "not_analyzed"),
        ("policy_evaluate", ""),
        ("policy_evaluate", "evaluation_queued"),
        ("image_status", ""),
        ("image_status", "deleting"),
        ("service_status", ""),
        ("service_status", "registered"),
        ("policy_engine_state", ""),
        ("policy_engine_state", "syncing"),
    ],
)
def test_next_state(state_type, current):
    if not current:
        assert (
            next_state(state_type, current)
            == state_graphs[state_type]["transitions"]["init"]
        )
    else:
        assert (
            next_state(state_type, current)
            == state_graphs[state_type]["transitions"][current]
        )


@pytest.mark.parametrize(
    "state_type",
    [
        "analyze",
        "policy_evaluate",
        "image_status",
        "service_status",
        "policy_engine_state",
    ],
)
def test_complete_state(state_type):
    assert complete_state(state_type) == state_graphs[state_type]["complete_state"]


@pytest.mark.parametrize(
    "state_type",
    [
        "analyze",
        "policy_evaluate",
        "image_status",
        "service_status",
        "policy_engine_state",
    ],
)
def test_orphaned_state(state_type):
    if "orphaned_state" in state_graphs[state_type]:
        assert orphaned_state(state_type) == state_graphs[state_type]["orphaned_state"]
    else:
        assert orphaned_state(state_type) == state_graphs[state_type]["fault_state"]
