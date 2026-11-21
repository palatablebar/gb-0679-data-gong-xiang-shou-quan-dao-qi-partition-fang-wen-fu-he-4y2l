import json

import pytest

from app import store
from app.errors import DomainError
from app.pipeline import calculate, load_sample
from app.modules.m8_deliveries import rules


@pytest.fixture
def run(): return calculate(load_sample("dirty.csv"))


def by_key(result): return {d["partition_key"]: d for d in result["deliveries"]}


def test_every_delivery_partition_is_decided(run):
    result = rules.evaluate(run)
    keys = {d["partition_key"] for d in result["deliveries"]}
    assert keys == {"orders:2026-10", "orders:2026-09", "customers:2026-05", "orders:2026-05"}
    assert all(d["decision"] in {rules.PUBLISHABLE, rules.PENDING, rules.BLOCKED} for d in result["deliveries"])


def test_all_sources_authorized_is_publishable(run):
    result = by_key(rules.evaluate(run))
    allowed = result["orders:2026-09"]
    assert allowed["decision"] == rules.PUBLISHABLE
    assert allowed["basis"]["authorized_count"] == allowed["basis"]["source_count"] == 8
    assert allowed["reconciliation"]["difference"] == "0"


def test_one_unauthorized_source_blocks_whole_partition(run):
    result = by_key(rules.evaluate(run))
    mixed = result["orders:2026-05"]
    assert mixed["decision"] == rules.BLOCKED
    assert mixed["reason"] == "存在未获准来源"
    assert mixed["basis"]["authorized_count"] == 0
    # 合法来源没有被静默丢弃：仍列在来源清单与证据行里
    assert len(mixed["sources"]) == len(mixed["rows"]) == 8
    assert len(mixed["basis"]["unauthorized_events"]) == 8


def test_name_allow_does_not_override_expired_grant(run):
    """按分区名重新申请权限会捡到宽授权；本项目按来源逐条复算，不放行。"""
    result = by_key(rules.evaluate(run))
    mixed = result["orders:2026-05"]
    assert "G-01" not in mixed["basis"]["matched_rules"]
    assert mixed["decision"] != rules.PUBLISHABLE


def test_source_shortfall_keeps_pending(run):
    result = by_key(rules.evaluate(run))
    # 2026-10 有一条重复冲突行（43 行）被隔离，来源不齐
    pending = result["orders:2026-10"]
    assert pending["decision"] == rules.PENDING
    assert pending["reason"] == "来源未补齐"
    assert set(pending["quarantined_sources"]) == {39, 40, 41, 43}


def test_declared_source_list_shortfall_is_pending(run):
    declared = [{"resource": "orders", "partition": "2026-09", "sources": [4, 8]}]
    result = by_key(rules.evaluate(run, declared))
    entry = result["orders:2026-09"]
    assert entry["decision"] == rules.PENDING
    assert entry["reason"] == "来源清单未覆盖全部来源行"
    assert entry["declared_not_arrived"] == []
    assert entry["not_in_declared"] == sorted([12, 16, 20, 24, 28, 32])
    assert entry["declared_sources"] == [4, 8]
    assert entry["declared_sha256"] == rules.source_list_sha256([4, 8])
    # 证据与三处摘要仍绑定实际证据行来源，不因声明缺行而改写
    assert entry["source_list_sha256"] == rules.source_list_sha256(entry["sources"])
    assert entry["sources"] == sorted([4, 8, 12, 16, 20, 24, 28, 32])


def test_declared_source_list_must_cover_all_sources(run):
    declared = [{"resource": "orders", "partition": "2026-09", "sources": list(range(1, 40))}]
    entry = by_key(rules.evaluate(run, declared))["orders:2026-09"]
    assert entry["decision"] == rules.PENDING
    assert entry["reason"] == "来源未补齐"
    assert entry["declared_not_arrived"]
    assert entry["not_in_declared"] == []
    assert entry["source_list_sha256"] == rules.source_list_sha256(entry["sources"])


def test_evidence_binds_same_source_list(run):
    for entry in rules.evaluate(run)["deliveries"]:
        digest = entry["source_list_sha256"]
        assert entry["basis"]["sources_sha256"] == digest
        assert entry["reconciliation"]["sources_sha256"] == digest
        row_lines = sorted({x for row in entry["rows"] for x in row["_sources"]})
        assert row_lines == sorted(entry["sources"])
        ok, problems = rules.verify_record(entry)
        assert ok, problems


def test_tampered_evidence_fails_verification(run):
    entry = by_key(rules.evaluate(run))["orders:2026-09"]
    tampered = json.loads(json.dumps(entry))
    tampered["rows"][0]["expected"] = "1"
    tampered["rows"][0]["observed"] = "blocked"
    ok, problems = rules.verify_record(tampered)
    assert not ok and problems


def test_source_list_bound_into_row_digest(run):
    entry = by_key(rules.evaluate(run))["orders:2026-09"]
    changed = json.loads(json.dumps(entry))
    changed["sources"] = sorted(entry["sources"])[:-1]
    ok, problems = rules.verify_record(changed)
    assert not ok and "来源清单与证据行来源不一致" in problems


def test_repeat_publish_reuses_record(run):
    entry = by_key(rules.evaluate(run))["orders:2026-09"]
    first = store.publish(entry)
    second = store.publish(by_key(rules.evaluate(run))["orders:2026-09"])
    assert first["reused"] is False and second["reused"] is True
    assert len(store.publications()) == 1
    assert store.publication("orders:2026-09")["version"] == 1


def test_pending_is_not_published(run):
    pending = by_key(rules.evaluate(run))["orders:2026-10"]
    kept = store.keep_pending(pending)
    assert kept["published"] is False
    assert store.publications() == []


def test_replacement_keeps_old_version_and_basis(run):
    entry = by_key(rules.evaluate(run))["orders:2026-09"]
    first = store.publish(entry)
    changed = json.loads(json.dumps(entry))
    changed["decision"] = rules.PUBLISHABLE
    changed["reason"] = "复核后沿用"
    changed["idempotency"] = "different"
    changed["evaluated_at"] = "2026-11-21T00:00:00+00:00"
    second = store.publish(changed)
    assert second["version"] == 2 and second["reused"] is False
    assert second["record"]["reason"] == "复核后沿用"
    history = store.publication("orders:2026-09")["superseded"]
    assert len(history) == 1
    assert history[0]["version"] == 1
    assert history[0]["evidence_sha256"] == first["evidence_sha256"]
    assert history[0]["record"]["basis"] == entry["basis"]


def test_failed_replacement_keeps_old_record(run, monkeypatch):
    entry = by_key(rules.evaluate(run))["orders:2026-09"]
    store.publish(entry)
    before = store.publication("orders:2026-09")
    changed = json.loads(json.dumps(entry))
    changed["evaluated_at"] = "2026-11-21T00:00:00+00:00"
    changed["idempotency"] = "forced-replacement"

    def broken(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(store, "_write_active", broken)
    with pytest.raises(DomainError) as error:
        store.publish(changed)
    assert error.value.code == "PUBLISH_FAILED"
    after = store.publication("orders:2026-09")
    assert after["version"] == before["version"]
    assert after["evidence_sha256"] == before["evidence_sha256"]
    assert after["record"]["basis"] == entry["basis"]
    assert store.publication("orders:2026-09")["superseded"] == []


def test_tampered_record_refuses_publish(run):
    entry = by_key(rules.evaluate(run))["orders:2026-09"]
    tampered = json.loads(json.dumps(entry))
    tampered["rows"][0]["reported"] = "0"
    with pytest.raises(DomainError) as error:
        store.publish(tampered)
    assert error.value.code == "EVIDENCE_MISMATCH"
    assert store.publications() == []


def test_unbalanced_run_keeps_all_pending(run):
    broken = json.loads(json.dumps(run, default=str))
    broken["stages"][5]["metrics"]["balanced"] = False
    result = rules.evaluate(broken)
    assert all(d["decision"] == rules.PENDING for d in result["deliveries"])


def test_unattributed_invalid_partition_reported(run):
    result = rules.evaluate(run)
    assert 42 in result["summary"]["unattributed_sources"]
    assert result["summary"]["complete"] is False


def test_api_endpoints(client):
    created = client.post("/api/runs", json={"sample": "dirty.csv"}).get_json()
    listed = client.get("/api/deliveries").get_json()
    assert {d["partition_key"] for d in listed["deliveries"]} >= {"orders:2026-09"}
    response = client.post("/api/deliveries/publish", json={"run_id": created["run_id"]}).get_json()
    assert response["summary"]["publishable"] == 2
    outcomes = {r["partition_key"]: r for r in response["results"]}
    assert outcomes["orders:2026-09"]["published"] is True
    assert outcomes["orders:2026-10"]["published"] is False
    assert outcomes["orders:2026-05"]["published"] is False
    assert outcomes["orders:2026-10"]["active_version"] == 0
    records = client.get("/api/deliveries/records").get_json()["publications"]
    assert len(records) == 2
    again = client.post("/api/deliveries/publish", json={"run_id": created["run_id"]}).get_json()
    assert {r["partition_key"]: r["reused"] for r in again["results"]}["orders:2026-09"] is True
    assert len(client.get("/api/deliveries/records").get_json()["publications"]) == 2


def test_api_archive_binds_sources(client):
    created = client.post("/api/runs", json={"sample": "dirty.csv"}).get_json()
    client.post("/api/deliveries/publish", json={"run_id": created["run_id"]})
    record = client.get("/api/deliveries/record/orders:2026-09").get_json()
    response = client.get("/api/deliveries/record/orders:2026-09/archive")
    assert response.status_code == 200
    body = response.data.decode("utf-8-sig")
    lines = body.strip().splitlines()
    assert len(lines) == 1 + len(record["record"]["rows"])
    assert record["source_list_sha256"] in lines[1]
    assert json.dumps(sorted(record["record"]["sources"])) in lines[1]


def test_api_bad_declared_sources(client):
    client.post("/api/runs", json={"sample": "dirty.csv"})
    response = client.post("/api/deliveries/publish", json={"partitions": [
        {"resource": "orders", "partition": "2026-09", "sources": [4]},
        {"resource": "customers", "partition": "2026-05", "sources": [4]},
    ]})
    assert response.status_code == 422
    assert response.get_json()["code"] == "BAD_SOURCE_LIST"


def test_pending_cannot_be_published(run):
    pending = by_key(rules.evaluate(run))["orders:2026-10"]
    with pytest.raises(DomainError) as error:
        store.publish(pending)
    assert "NOT_PUBLISHABLE" in str(error.value.code)


def test_declared_shortfall_does_not_publish(client):
    client.post("/api/runs", json={"sample": "dirty.csv"})
    declared = [{"resource": "orders", "partition": "2026-09", "sources": [4, 8]}]
    listed = client.post("/api/deliveries", json={"partitions": declared}).get_json()
    entry = {d["partition_key"]: d for d in listed["deliveries"]}["orders:2026-09"]
    assert entry["decision"] == rules.PENDING
    assert entry["declared_sha256"] == rules.source_list_sha256([4, 8])
    records = client.get("/api/deliveries/records").get_json()["publications"]
    assert "orders:2026-09" not in {r["partition_key"] for r in records}
