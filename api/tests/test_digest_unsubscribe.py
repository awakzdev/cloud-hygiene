from app.services.digest import _unsubscribe_url
from app.services.digest_tokens import ensure_digest_unsubscribe_token


def test_unsubscribe_url_uses_token_when_present():
    url = _unsubscribe_url("abc123token456789012345678")
    assert "token=abc123token456789012345678" in url
    assert "/v1/public/digest/unsubscribe" in url


def test_unsubscribe_url_falls_back_to_settings_without_token():
    url = _unsubscribe_url(None)
    assert url.endswith("/settings")


def test_ensure_digest_token_created_when_enabled():
    out = ensure_digest_unsubscribe_token({"email_digest_enabled": True})
    assert out.get("digest_unsubscribe_token")
    assert len(out["digest_unsubscribe_token"]) >= 32
