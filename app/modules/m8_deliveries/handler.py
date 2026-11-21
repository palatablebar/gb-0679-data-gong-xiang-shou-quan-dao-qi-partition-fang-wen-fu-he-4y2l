from flask import Blueprint, request, jsonify, Response
from app.errors import DomainError
from app import store
from app.modules.m8_deliveries import rules
from app.archive import build_delivery_archive
bp = Blueprint("deliveries", __name__)


def _payload():
    if request.method != "POST":
        return {}
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise DomainError("BAD_BODY", "请求需要对象")
    return payload


def _run(payload):
    run_id = payload.get("run_id")
    if run_id:
        if not isinstance(run_id, str):
            raise DomainError("BAD_RUN", "批次号需要文本")
        return store.get(run_id)
    run = store.latest()
    if run:
        return run
    from app.pipeline import calculate, load_sample
    return calculate(load_sample("dirty.csv"))


def _evaluate(payload):
    run = _run(payload)
    return run, rules.evaluate(run, payload.get("partitions"))


@bp.route("/api/deliveries", methods=["GET", "POST"])
def preview():
    return jsonify(_evaluate(_payload())[1])


@bp.route("/api/deliveries/publish", methods=["POST"])
def publish():
    run, result = _evaluate(_payload())
    results = []
    for record in result["deliveries"]:
        item = {"partition_key": record["partition_key"], "decision": record["decision"],
                "code": record["code"], "reason": record["reason"],
                "evidence_sha256": record["evidence_sha256"],
                "source_list_sha256": record["source_list_sha256"]}
        if record["decision"] == rules.PUBLISHABLE:
            stored = store.publish(record)
            item.update(published=True, reused=stored.get("reused", False),
                        version=stored["version"], evidence_sha256=stored["evidence_sha256"],
                        source_list_sha256=stored["source_list_sha256"])
            item["active_version"] = stored["version"]
        else:
            if record["decision"] == rules.PENDING:
                store.keep_pending(record)
            active = [p for p in store.publications() if p["partition_key"] == record["partition_key"]]
            item.update(published=False, reused=False,
                        active_version=active[0]["version"] if active else 0)
        results.append(item)
    return jsonify({"run_id": run["run_id"], "summary": result["summary"], "results": results})


@bp.route("/api/deliveries/records", methods=["GET"])
def records():
    return jsonify({"publications": store.publications()})


@bp.route("/api/deliveries/record/<path:partition_key>", methods=["GET"])
def record(partition_key):
    return jsonify(store.publication(partition_key))


@bp.route("/api/deliveries/record/<path:partition_key>/archive", methods=["GET"])
def archive(partition_key):
    stored = store.publication(partition_key)
    body = build_delivery_archive([stored["record"]])
    filename = partition_key.replace(":", "_") + ".csv"
    return Response(body, mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
