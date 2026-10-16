from engine import approval


def test_no_pause_when_mode_off():
    class O:
        approval_mode = False
    assert approval.should_pause({"tool": "race_scan"}, O()) is False


def test_pause_destructive_when_mode_on():
    class O:
        approval_mode = True
    assert approval.should_pause({"tool": "race_scan"}, O()) is True


def test_no_pause_read_only_when_mode_on():
    class O:
        approval_mode = True
    assert approval.should_pause({"tool": "security-headers-missing"}, O()) is False


def test_none_obj_safe():
    assert approval.should_pause({"tool": "race_scan"}, None) is False


def test_non_dict_step_safe():
    class O:
        approval_mode = True
    assert approval.should_pause("not-a-dict", O()) is False


def test_empty_step_safe():
    class O:
        approval_mode = True
    assert approval.should_pause({}, O()) is False


def test_record_pending_and_mark_approved():
    class O:
        pending_approval = []
    o = O()
    approval.record_pending(o, "chain-1", {"id": "s1", "tool": "race_scan"})
    assert len(o.pending_approval) == 1
    assert approval.is_approved(o, "chain-1", "s1") is False
    assert approval.mark_approved(o, "chain-1", "s1") is True
    assert approval.is_approved(o, "chain-1", "s1") is True


def test_record_pending_idempotent_fields():
    class O:
        pending_approval = []
    o = O()
    approval.record_pending(o, "c", {"id": "s", "tool": "t", "args": {"x": 1}})
    entry = o.pending_approval[0]
    assert entry["chain"] == "c"
    assert entry["step"] == "s"
    assert entry["tool"] == "t"
    assert entry["args"] == {"x": 1}
    assert entry["approved"] is False
