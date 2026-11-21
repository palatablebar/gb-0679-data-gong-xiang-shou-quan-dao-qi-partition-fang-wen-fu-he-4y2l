"""交付分区发布判定。

分区合并会把多个来源行压成一个只保留资源与分区名的交付分区。发布判定不能
只看分区名：授权按来源行的主体、资源、分区窗和生效窗逐条复算，只有参与合并
的每一条来源行都已核准，才沿用允许结论；任一条来源未获准，整份交付分区不可
发布。这里选择合取（all-of）而非给最终分区重新申请权限——分区名不是授权
主体，按名称重新申请可能命中覆盖到期时段的宽授权，把到期数据送出。

来源清单不完整时保持待核：不按名称放行，也不静默丢掉合法来源。

核准依据（basis）、核对结果（reconciliation）和对外证据（rows）三处都绑定
同一份排序后的来源清单，各自保存 source_list_sha256；发布与导出时逐项复核。
"""
import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from app.errors import DomainError
from app.modules.m2_resources.rules import RESOURCES
from app.reasons import sources as row_sources

PUBLISHABLE = "可发布"
PENDING = "待核"
BLOCKED = "不可发布"
CODE = {PUBLISHABLE: "publishable", PENDING: "pending", BLOCKED: "blocked"}
DELIVERY_STATE = {PUBLISHABLE: "发布", PENDING: "不发布·待核", BLOCKED: "不发布·阻断"}

POLICY = "all_sources_authorized"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def sha256_json(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def valid_partition(part):
    if not isinstance(part, str) or len(part) != 7 or part[4] != "-":
        return False
    if not part[:4].isdigit() or not part[5:].isdigit():
        return False
    return 1 <= int(part[5:]) <= 12


def partition_key(resource, partition):
    return f"{resource}:{partition}"


def source_list_sha256(listed):
    return sha256_json(sorted(int(x) for x in listed))


def _source_int(value):
    if isinstance(value, bool):
        raise DomainError("BAD_SOURCE_LIST", "来源清单必须是来源行号")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    raise DomainError("BAD_SOURCE_LIST", "来源清单必须是来源行号")


def _parse_declared(declared):
    """解析调用方声明的来源清单，返回 {partition_key: set(source_line)} 或 None。"""
    if declared is None:
        return None
    if not isinstance(declared, list):
        raise DomainError("BAD_DELIVERY", "partitions 需要对象列表")
    parsed = {}
    owner = {}
    for entry in declared:
        if not isinstance(entry, dict):
            raise DomainError("BAD_DELIVERY", "交付分区需要对象")
        resource = RESOURCES.get(entry.get("resource"))
        partition = entry.get("partition")
        if not resource:
            raise DomainError("BAD_DELIVERY", "交付分区资源未登记")
        if not valid_partition(partition):
            raise DomainError("BAD_DELIVERY", "交付分区必须为YYYY-MM")
        key = partition_key(resource, partition)
        if key in parsed:
            raise DomainError("BAD_DELIVERY", "同一交付分区重复声明")
        listed = entry.get("sources", [])
        if not isinstance(listed, list):
            raise DomainError("BAD_SOURCE_LIST", "来源清单需要列表")
        numbers = {_source_int(x) for x in listed}
        for number in numbers:
            if number in owner and owner[number] != key:
                raise DomainError("BAD_SOURCE_LIST", "同一来源行不能属于两个交付分区")
            owner[number] = key
        parsed[key] = numbers
    return parsed


def _quarantine_index(quarantine):
    """按来源行把隔离记录归到交付分区。

    - 资源已登记且分区合法：直接归属该 resource:partition；
    - 分区合法但资源未登记：可能属于该分区的任一资源，逐份标记待核；
    - 分区非法或缺失：无法归属任何交付分区，单独列入 summary.unattributed。
    """
    exact, by_partition, unattributed = {}, {}, []
    for row in quarantine:
        partition = row.get("partition")
        if not valid_partition(partition):
            unattributed.append(row)
            continue
        resource = RESOURCES.get(row.get("resource"))
        if resource:
            exact.setdefault(partition_key(resource, partition), []).append(row)
        else:
            by_partition.setdefault(partition, []).append(row)
    return exact, by_partition, unattributed


def _sources_of(rows):
    return sorted({int(x) for row in rows for x in row_sources(row)})


def _effect(rows):
    effects = {row.get("effect") for row in rows}
    if effects == {"allow"}:
        return "allow"
    if effects == {"deny"}:
        return "deny"
    if not effects:
        return "none"
    return "mixed"


def _basis(run, key, source_list, rows):
    return {
        "policy": POLICY,
        "description": "仅当全部来源行均已核准时沿用允许结论",
        "run_id": run["run_id"],
        "input_sha256": run["manifest"]["input_sha256"],
        "rule_version": run["manifest"]["rule_version"],
        "partition_key": key,
        "effect": _effect(rows),
        "matched_rules": sorted({rule for row in rows for rule in row.get("matched_rules", [])}),
        "allow_rules": sorted({rule for row in rows for rule in row.get("allow_rules", [])}),
        "deny_rules": sorted({rule for row in rows for rule in row.get("deny_rules", [])}),
        "candidate_rules": sorted({rule["id"] for row in rows for rule in row.get("candidates", [])}),
        "principals": sorted({row.get("principal", "") for row in rows}),
        "events": sorted(str(row.get("event_id", "")) for row in rows),
        "source_count": len(source_list),
        "authorized_count": sum(1 for row in rows if row.get("effect") == "allow"),
        "unauthorized_events": sorted(str(row.get("event_id", "")) for row in rows if row.get("effect") != "allow"),
        "sources_sha256": source_list_sha256(source_list),
    }


def _decimal(value):
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise DomainError("BAD_EVIDENCE", "核对数值无效")


def _reconciliation(source_list, rows):
    expected = sum((_decimal(row.get("expected", "0")) for row in rows), Decimal(0))
    reported = sum((_decimal(row.get("reported", "0")) for row in rows), Decimal(0))
    return {
        "expected_total": str(expected),
        "reported_total": str(reported),
        "difference": str(expected - reported),
        "differences": sum(1 for row in rows if row.get("status") == "差异"),
        "violations": sum(1 for row in rows if row.get("violation") in {"越权放行", "误拦截"}),
        "sources_sha256": source_list_sha256(source_list),
    }


EVIDENCE_FIELDS = (
    "event_id", "principal", "resource", "partition", "access_time", "observed", "at",
    "expected", "upstream_decision", "reported", "effect", "matched_rules", "deny_rules",
    "allow_rules", "rule_evidence", "partition_result", "violation", "status", "difference",
)


def _evidence_rows(rows):
    evidence = []
    for row in rows:
        item = {field: row.get(field) for field in EVIDENCE_FIELDS if field in row}
        item["_sources"] = list(row_sources(row))
        evidence.append(item)
    return evidence


def evidence_digest(key, run_id, input_sha256, rule_version, source_list, declared, basis, reconciliation, rows):
    return sha256_json({
        "partition_key": key,
        "run_id": run_id,
        "input_sha256": input_sha256,
        "rule_version": rule_version,
        "sources": sorted(int(x) for x in source_list),
        "declared": None if declared is None else sorted(int(x) for x in declared),
        "basis": basis,
        "reconciliation": reconciliation,
        "rows": rows,
    })


def idempotency_key(key, run, source_list, declared, basis, reconciliation):
    """同一交付分区、同一批次、同一来源清单与依据得到同一个幂等键。

    不含 evaluated_at 等时间戳，因此重跑相同输入会复用已有发布记录。
    """
    return sha256_json({
        "partition_key": key,
        "run_id": run["run_id"],
        "input_sha256": run["manifest"]["input_sha256"],
        "rule_version": run["manifest"]["rule_version"],
        "sources": sorted(int(x) for x in source_list),
        "declared": None if declared is None else sorted(int(x) for x in declared),
        "effect": basis["effect"],
        "matched_rules": basis["matched_rules"],
        "deny_rules": basis["deny_rules"],
        "expected_total": reconciliation["expected_total"],
        "reported_total": reconciliation["reported_total"],
    })


def verify_record(record):
    """复核发布记录中依据、核对与证据三处是否绑定同一份来源清单。"""
    problems = []
    try:
        sources = sorted(int(x) for x in record.get("sources", []))
        row_sources_all = sorted({int(x) for row in record.get("rows", []) for x in row.get("_sources", [])})
        basis = record.get("basis") or {}
        reconciliation = record.get("reconciliation") or {}
        rows = record.get("rows") or []
        digest = source_list_sha256(sources)
        if sources != row_sources_all:
            problems.append("来源清单与证据行来源不一致")
        if digest != record.get("source_list_sha256"):
            problems.append("来源清单摘要不匹配")
        if basis.get("sources_sha256") != digest:
            problems.append("核准依据未绑定同一来源清单")
        if reconciliation.get("sources_sha256") != digest:
            problems.append("核对结果未绑定同一来源清单")
        expected = sum((_decimal(row.get("expected", "0")) for row in rows), Decimal(0))
        reported = sum((_decimal(row.get("reported", "0")) for row in rows), Decimal(0))
        if str(expected) != str(reconciliation.get("expected_total")):
            problems.append("核对预期合计与证据行不一致")
        if str(reported) != str(reconciliation.get("reported_total")):
            problems.append("核对申报合计与证据行不一致")
        declared = record.get("declared_sources")
        if declared is not None:
            if source_list_sha256(declared) != record.get("declared_sha256"):
                problems.append("声明来源清单摘要不匹配")
        recomputed = evidence_digest(
            record.get("partition_key"), record.get("run_id"), record.get("input_sha256"),
            record.get("rule_version"), sources, declared, basis, reconciliation, rows,
        )
        if recomputed != record.get("evidence_sha256"):
            problems.append("证据摘要不匹配")
        if record.get("decision") not in {PUBLISHABLE, PENDING, BLOCKED}:
            problems.append("发布结论无效")
    except (DomainError, TypeError, ValueError, KeyError) as error:
        problems.append(f"证据结构无效：{error}")
    return (not problems, problems)


def _decide(key, resource, partition, rows, declared, own_quarantine, unknown_quarantine, balanced, run):
    # 证据清单始终取证据行实际覆盖的来源行；调用方声明的清单单独记录，
    # 用于发现“来源未补齐/清单未覆盖全部来源行”，不混入证据摘要。
    actual = _sources_of(rows)
    declared_list = None if declared is None else sorted(declared)
    quarantined = sorted({int(x) for row in own_quarantine for x in row_sources(row)})

    reason = ""
    if not balanced:
        reason = "来源行未对平"
    elif declared is not None:
        if declared - set(actual):
            reason = "来源未补齐"
        elif set(actual) - declared:
            reason = "来源清单未覆盖全部来源行"
    if not reason and (quarantined or unknown_quarantine):
        reason = "来源未补齐"
    if not reason and not rows:
        reason = "来源未补齐"

    basis = _basis(run, key, actual, rows)
    reconciliation = _reconciliation(actual, rows)
    evidence = _evidence_rows(rows)

    if reason:
        decision = PENDING
    elif any(row.get("effect") != "allow" for row in rows):
        decision = BLOCKED
        reason = "存在未获准来源"
    elif reconciliation["differences"] or reconciliation["violations"]:
        decision = BLOCKED
        reason = "核对结果存在差异"
    else:
        decision = PUBLISHABLE

    record = {
        "partition_key": key,
        "resource": resource,
        "partition": partition,
        "decision": decision,
        "code": CODE[decision],
        "reason": reason,
        "policy": POLICY,
        "sources": actual,
        "source_list_sha256": source_list_sha256(actual),
        "declared_sources": declared_list,
        "declared_sha256": None if declared_list is None else source_list_sha256(declared_list),
        "basis": basis,
        "reconciliation": reconciliation,
        "rows": evidence,
        "declared_not_arrived": sorted(declared - set(actual)) if declared is not None else [],
        "not_in_declared": sorted(set(actual) - declared) if declared is not None else [],
        "quarantined_sources": sorted(set(quarantined) | {int(x) for row in unknown_quarantine for x in row_sources(row)}),
        "delivery_state": DELIVERY_STATE[decision],
        "run_id": run["run_id"],
        "input_sha256": run["manifest"]["input_sha256"],
        "rule_version": run["manifest"]["rule_version"],
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
    record["evidence_sha256"] = evidence_digest(
        key, run["run_id"], run["manifest"]["input_sha256"], run["manifest"]["rule_version"],
        actual, declared_list, basis, reconciliation, evidence,
    )
    record["idempotency"] = idempotency_key(key, run, actual, declared_list, basis, reconciliation)
    return record


def evaluate(run, declared=None):
    """对一份运行的交付分区逐份判定。返回 {deliveries, summary}。"""
    stage = run["stages"][5]
    rows = stage["rows"]
    quarantine = stage.get("cumulative_quarantine") or []
    balanced = bool(stage.get("metrics", {}).get("balanced", True))

    groups, order = {}, []
    for row in rows:
        key = partition_key(row["resource"], row["partition"])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(row)

    exact, by_partition, unattributed = _quarantine_index(quarantine)
    declared_map = _parse_declared(declared)

    for key in exact:
        if key not in groups and key not in order:
            order.append(key)
    if declared_map is not None:
        for key in declared_map:
            if key not in groups and key not in order:
                order.append(key)

    # 资源未登记的隔离行只有在同一分区存在已知资源时才能归属；否则无法归入
    # 任何交付分区，列入 unattributed，避免静默丢失。
    known_partitions = {key.split(":", 1)[1] for key in order}
    for partition in list(by_partition):
        if partition not in known_partitions:
            unattributed.extend(by_partition.pop(partition))

    deliveries = []
    for key in order:
        resource, partition = key.split(":", 1)
        record = _decide(
            key, resource, partition, groups.get(key, []),
            declared_map.get(key) if declared_map is not None else None,
            exact.get(key, []), by_partition.get(partition, []), balanced, run,
        )
        deliveries.append(record)

    unattributed_sources = sorted({int(x) for row in unattributed for x in row_sources(row)})
    summary = {
        "total": len(deliveries),
        "publishable": sum(1 for d in deliveries if d["decision"] == PUBLISHABLE),
        "pending": sum(1 for d in deliveries if d["decision"] == PENDING),
        "blocked": sum(1 for d in deliveries if d["decision"] == BLOCKED),
        "source_lists": sum(len(d["sources"]) for d in deliveries),
        "unattributed_sources": unattributed_sources,
        "complete": bool(balanced) and not unattributed_sources,
        "policy": POLICY,
    }
    return {"deliveries": deliveries, "summary": summary}
