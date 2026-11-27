from redteam.errors import record_suppressed_error


class Audit:
    def __init__(self):
        self.events = []

    def record(self, event, **fields):
        self.events.append((event, fields))


def test_suppressed_error_is_a_structured_redacted_audit_event():
    audit = Audit()
    record_suppressed_error(
        audit, "browser", "capture_exchange",
        RuntimeError("Authorization: Bearer super-secret-value and ?access_token=also-secret"),
        url="https://lab.invalid/path?token=query-secret",
    )
    event, fields = audit.events[0]
    assert event == "runtime.error.suppressed"
    assert fields["component"] == "browser"
    assert fields["operation"] == "capture_exchange"
    assert fields["exception_type"] == "RuntimeError"
    serialized = str(fields)
    for secret in ("super-secret-value", "also-secret", "query-secret"):
        assert secret not in serialized
    assert "<redacted>" in serialized


def test_error_event_falls_back_to_logger_when_audit_sink_fails(caplog):
    class BrokenAudit:
        def record(self, *args, **kwargs):
            raise OSError("audit disk full")

    record_suppressed_error(BrokenAudit(), "proxy", "record", RuntimeError("failed"))
    assert "contained runtime failure" in caplog.text
    assert "audit_error_type" in str(caplog.records[-1].redteam_event)
