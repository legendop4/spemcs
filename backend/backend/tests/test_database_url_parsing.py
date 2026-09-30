"""Regression test for database URL parsing during startup diagnostic logging.

Reproduces and guards against the ValueError crash caused by urlparse() when
passwords contain URL-special characters (e.g., colons, exclamation marks, @, #).
"""

from urllib.parse import urlparse
import pytest
from sqlalchemy.engine import make_url

from backend.app.database import extract_db_host_port


SCHEME = "postgresql" + "://"


def test_urlparse_reproduces_value_error_on_special_characters():
    """Demonstrate that standard urlparse fails on passwords with unescaped colons."""
    # Standard urlparse fails when password contains unencoded colons:
    # ValueError: Port could not be cast to integer value
    u = "test_user"
    p = "spec!al:complex#pass"
    h = "db.example.internal"
    tricky_url = f"{SCHEME}{u}:{p}@{h}:5432/spemcs"
    parsed = urlparse(tricky_url)
    with pytest.raises(ValueError, match="Port could not be cast to integer value"):
        _ = parsed.port


def test_extract_db_host_port_handles_special_char_passwords():
    """Verify that extract_db_host_port safely extracts host and port without error."""
    u = "test_user"
    h1 = "db.example.internal"
    h2 = "db.internal"
    h3 = "10.50.21.5"

    p1 = "spec!al:complex#pass"
    p2 = "p%40ssw%3Ard"
    p3 = "regularpassword"
    p4 = "spec!al:pass"

    tricky_urls = [
        f"{SCHEME}{u}:{p1}@{h1}:5432/spemcs",
        f"{SCHEME}{u}:{p2}@{h2}:5433/spemcs",
        f"{SCHEME}{u}:{p3}@{h3}:5432/spemcs",
        f"{SCHEME}{u}:{p4}@{h2}/spemcs",
    ]

    for url_str in tricky_urls:
        host, port = extract_db_host_port(url_str)
        assert isinstance(host, str)
        assert isinstance(port, int)
        # Ensure password is never leaked into host or port
        assert "spec!al" not in host
        assert "complex" not in host
        assert "p%40ssw" not in host
        assert "regularpassword" not in host
        assert str(port) not in ("spec!al", "complex")


def test_extract_db_host_port_from_engine_like_object():
    """Verify that extract_db_host_port works directly from an Engine or URL object."""
    from types import SimpleNamespace

    u = "test_user"
    p = "spec!al:complex"
    h = "db.example.internal"
    parsed_url = make_url(f"{SCHEME}{u}:{p}@{h}:5432/spemcs")
    mock_engine = SimpleNamespace(url=parsed_url)

    host, port = extract_db_host_port(mock_engine)
    assert host == "db.example.internal"
    assert port == 5432
    assert "spec!al" not in host


def test_extract_db_host_port_fallback_on_invalid_input():
    """Verify fallback behavior when provided invalid or empty inputs."""
    # Completely broken string
    host, port = extract_db_host_port("not_a_valid_url")
    assert host == "127.0.0.1"
    assert port == 5432

    # None or empty
    host, port = extract_db_host_port("")
    assert host == "127.0.0.1"
    assert port == 5432


def test_extract_db_host_port_logs_only_static_message_on_error(caplog):
    """Verify that on error, only a static message is logged and no exception/credentials leak."""
    import logging

    class BrokenEngine:
        @property
        def url(self):
            raise RuntimeError("Sensitive error with secret_pass_xyz123")

    with caplog.at_level(logging.WARNING, logger="backend.app.database"):
        host, port = extract_db_host_port(BrokenEngine())

    assert host == "127.0.0.1"
    assert port == 5432
    assert "Could not extract database host/port for diagnostic logging" in caplog.text
    assert "secret_pass_xyz123" not in caplog.text
    assert "Sensitive error" not in caplog.text


