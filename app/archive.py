import csv,io,json
from app.errors import DomainError
from app.modules.m8_deliveries import rules as delivery_rules
def build_archive(run):
    stream=io.StringIO(newline="");writer=csv.writer(stream)
    writer.writerow(["run_id","input_sha256","rule_version","kind","source_lines","reason","evidence"])
    meta=run["manifest"]
    for row in run["stages"][-1]["rows"]:
        writer.writerow([run["run_id"],meta["input_sha256"],meta["rule_version"],"accepted",json.dumps(row.get("_sources",[])),row.get("status",""),json.dumps(row,ensure_ascii=False)])
    for row in run["stages"][-1].get("cumulative_quarantine",[]):
        writer.writerow([run["run_id"],meta["input_sha256"],meta["rule_version"],"quarantine",json.dumps(row.get("_sources",[])),row.get("reason",""),json.dumps(row,ensure_ascii=False)])
    return "﻿"+stream.getvalue()

# 交付分区对外证据：每份分区绑定同一来源清单，导出前重新复核。
FIELDS=["partition_key","resource","partition","decision","code","reason","policy","source_list_sha256","sources","declared_sources","declared_sha256","evidence_sha256","run_id","input_sha256","rule_version","evaluated_at","authorized_count","source_count","expected_total","reported_total","difference","differences","violations","basis","reconciliation"]

def verify_delivery(record):
    ok,problems=delivery_rules.verify_record(record)
    if not ok: raise DomainError("EVIDENCE_MISMATCH","证据与来源清单不一致："+"；".join(problems))

def _delivery_row(record):
    basis=record.get("basis") or {};reconciliation=record.get("reconciliation") or {}
    return [record.get("partition_key"),record.get("resource"),record.get("partition"),record.get("decision"),record.get("code"),record.get("reason"),record.get("policy"),record.get("source_list_sha256"),json.dumps(record.get("sources",[])),json.dumps(record.get("declared_sources")),record.get("declared_sha256"),record.get("evidence_sha256"),record.get("run_id"),record.get("input_sha256"),record.get("rule_version"),record.get("evaluated_at"),basis.get("authorized_count"),basis.get("source_count"),reconciliation.get("expected_total"),reconciliation.get("reported_total"),reconciliation.get("difference"),reconciliation.get("differences"),reconciliation.get("violations"),json.dumps(basis,ensure_ascii=False,sort_keys=True),json.dumps(reconciliation,ensure_ascii=False,sort_keys=True)]

def build_delivery_archive(records):
    for record in records: verify_delivery(record)
    stream=io.StringIO(newline="");writer=csv.writer(stream)
    writer.writerow(FIELDS+["row_source_lines","row_evidence"])
    for record in records:
        head=_delivery_row(record)
        for row in record.get("rows",[]):
            writer.writerow(head+[json.dumps(row.get("_sources",[])),json.dumps(row,ensure_ascii=False,sort_keys=True)])
    return "﻿"+stream.getvalue()
