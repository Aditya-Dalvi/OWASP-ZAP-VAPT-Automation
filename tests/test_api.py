import pytest

pytest.importorskip("flask")
pytest.importorskip("zapv2")

from src.api import create_app


def test_health_endpoint_is_available_without_bearer_token():
    client = create_app("blackbox").test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_scan_endpoint_rejects_missing_bearer_token():
    client = create_app("blackbox").test_client()
    response = client.post("/scan", json={"url": "https://example.test"})
    assert response.status_code == 401
