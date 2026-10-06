"""API contract tests. Shapes here must match src/frontend/src/types.ts."""

from __future__ import annotations

import io

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from src.backend import store
from src.backend.config import EVENTS_CSV
from src.backend.main import app

pytestmark = pytest.mark.skipif(
    not EVENTS_CSV.exists(), reason="run: python -m src.scripts.generate_data"
)


@pytest.fixture(scope="module")
def client() -> TestClient:
    store.reset()
    return TestClient(app)


def test_health(client: TestClient) -> None:
    assert client.get("/api/health").json()["status"] == "ok"


def test_summary_reports_the_reduction(client: TestClient) -> None:
    body = client.get("/api/summary").json()
    assert body["total_events"] > 10_000
    assert body["campaigns"] > 0
    # The headline claim: thousands of events collapse to a handful of incidents.
    assert body["campaigns"] < 50
    assert set(body["by_tier"]) == {"critical", "high", "medium", "low"}


def test_campaigns_are_ranked_by_risk(client: TestClient) -> None:
    campaigns = client.get("/api/campaigns").json()
    assert campaigns
    risks = [c["risk"] for c in campaigns]
    assert risks == sorted(risks, reverse=True)
    first = campaigns[0]
    for field in ("campaign_id", "name", "technique", "tier", "event_count",
                  "source_ips", "usernames", "evidence"):
        assert field in first


def test_campaign_detail_carries_its_events_and_evidence(client: TestClient) -> None:
    campaign_id = client.get("/api/campaigns").json()[0]["campaign_id"]
    detail = client.get(f"/api/campaigns/{campaign_id}").json()
    assert detail["campaign_id"] == campaign_id
    assert len(detail["events"]) == detail["event_count"]
    assert detail["technique_name"]
    # Every alert must explain itself -- that is the product claim.
    assert any(event["evidence"] for event in detail["events"])


def test_unknown_campaign_is_404(client: TestClient) -> None:
    assert client.get("/api/campaigns/CAMP-999").status_code == 404


def test_events_filter_by_tier(client: TestClient) -> None:
    events = client.get("/api/events", params={"tier": "critical"}).json()
    assert all(event["tier"] == "critical" for event in events)


def test_audit_holds_only_below_gate_events(client: TestClient) -> None:
    """The suppression promise has to be inspectable, or it is just a claim."""
    body = client.get("/api/audit").json()
    assert body["total"] > 0
    assert all(0 < event["risk"] < 0.40 for event in body["events"])


def test_user_detail(client: TestClient) -> None:
    username = client.get("/api/events", params={"limit": 1}).json()[0]["username"]
    body = client.get(f"/api/users/{username}").json()
    assert body["username"] == username
    assert body["event_count"] > 0
    assert body["events"]


def test_replay_is_time_ordered(client: TestClient) -> None:
    steps = client.get("/api/replay").json()["steps"]
    assert steps
    stamps = [step["timestamp"] for step in steps]
    assert stamps == sorted(stamps)
    assert all(step["campaign_id"] for step in steps)


def test_upload_canonical_csv(client: TestClient) -> None:
    sample = pd.read_csv(EVENTS_CSV).head(3000)
    buffer = io.BytesIO(sample.to_csv(index=False).encode())
    response = client.post(
        "/api/analyze", files={"file": ("logs.csv", buffer, "text/csv")}
    )
    assert response.status_code == 200
    assert response.json()["source_format"] == "canonical"
    client.post("/api/reset")


def test_upload_entra_export_is_mapped(client: TestClient) -> None:
    """A real tenant export must flow through the same detectors unchanged."""
    source = pd.read_csv(EVENTS_CSV).head(3000)
    entra = pd.DataFrame({
        "TimeGenerated": source["timestamp"],
        "UserPrincipalName": source["username"],
        "IPAddress": source["source_ip"],
        "LocationDetails_countryOrRegion": source["country"],
        "LocationDetails_city": source["city"],
        "LocationDetails_geoCoordinates_latitude": source["latitude"],
        "LocationDetails_geoCoordinates_longitude": source["longitude"],
        # 50126 is the bad-credential code a spray generates.
        "ResultType": source["success"].map(lambda ok: "0" if ok else "50126"),
        "DeviceDetail_deviceId": source["device_id"],
        "UserAgent": source["user_agent"],
    })
    buffer = io.BytesIO(entra.to_csv(index=False).encode())
    response = client.post(
        "/api/analyze", files={"file": ("signins.csv", buffer, "text/csv")}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source_format"] == "entra"
    assert body["total_events"] > 0
    client.post("/api/reset")


def test_unrecognised_csv_is_rejected(client: TestClient) -> None:
    buffer = io.BytesIO(b"colour,size\nred,large\n")
    response = client.post(
        "/api/analyze", files={"file": ("junk.csv", buffer, "text/csv")}
    )
    assert response.status_code == 400


def test_inject_creates_a_new_campaign(client: TestClient) -> None:
    """The live demo moment: inject an attack, watch it get caught."""
    before = client.get("/api/summary").json()["campaigns"]
    body = client.post("/api/inject", params={"accounts": 40}).json()
    assert body["injected_events"] > 0
    assert body["campaign"] is not None
    assert body["campaign"]["technique"] == "T1110.003"
    assert body["summary"]["campaigns"] > before
    client.post("/api/reset")
