from app.common.request_context import (
    get_request_id,
    new_request_id,
    reset_request_id,
    set_request_id,
)


def test_request_id_generation() -> None:
    first = new_request_id()
    second = new_request_id()

    assert first != second
    assert len(first) == 36
    assert len(second) == 36


def test_request_context_propagation() -> None:
    request_id = new_request_id()

    token = set_request_id(request_id)

    try:
        assert get_request_id() == request_id
    finally:
        reset_request_id(token)


def test_request_context_default() -> None:
    assert get_request_id() == "-"
