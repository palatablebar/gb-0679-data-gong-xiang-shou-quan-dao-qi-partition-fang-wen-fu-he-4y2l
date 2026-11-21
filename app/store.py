import sqlite3,json
from pathlib import Path
from app.config import DATA_DIR
from app.errors import DomainError
def connect():
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(DATA_DIR/"records.db",timeout=20)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY,payload TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,decision TEXT NOT NULL DEFAULT '待复核')")
    db.execute("CREATE TABLE IF NOT EXISTS publications (partition_key TEXT PRIMARY KEY,payload TEXT NOT NULL,evidence_sha256 TEXT NOT NULL,source_list_sha256 TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,version INTEGER NOT NULL DEFAULT 1)")
    db.execute("CREATE TABLE IF NOT EXISTS publication_versions (partition_key TEXT NOT NULL,version INTEGER NOT NULL,payload TEXT NOT NULL,evidence_sha256 TEXT NOT NULL,source_list_sha256 TEXT NOT NULL,superseded_at TEXT NOT NULL,PRIMARY KEY (partition_key,version))")
    return db
def save(run_id,payload):
    with connect() as db:
        db.execute("INSERT OR IGNORE INTO runs(id,payload) VALUES (?,?)",(run_id,json.dumps(payload,ensure_ascii=False)))
    return get(run_id)
def get(run_id):
    with connect() as db: row=db.execute("SELECT payload,version,decision FROM runs WHERE id=?",(run_id,)).fetchone()
    if not row: raise DomainError("NOT_FOUND","批次不存在",404)
    return {**json.loads(row[0]),"version":row[1],"decision":row[2]}
def latest():
    with connect() as db: row=db.execute("SELECT id FROM runs ORDER BY rowid DESC LIMIT 1").fetchone()
    return get(row[0]) if row else None
def history():
    with connect() as db: return [{"run_id":i,"version":v,"decision":d} for i,v,d in db.execute("SELECT id,version,decision FROM runs ORDER BY rowid DESC")]
def review(run_id,version,decision):
    if decision not in {"已复核","退回复核"}: raise DomainError("BAD_DECISION","复核状态无效")
    with connect() as db:
        cursor=db.execute("UPDATE runs SET version=version+1,decision=? WHERE id=? AND version=?",(decision,run_id,version))
        if cursor.rowcount!=1:
            if not db.execute("SELECT 1 FROM runs WHERE id=?",(run_id,)).fetchone(): raise DomainError("NOT_FOUND","批次不存在",404)
            raise DomainError("STALE_VERSION","版本已更新，请刷新",409)
    return get(run_id)


def _publication_rows(db,partition_key):
    return [{"version":v,"evidence_sha256":e,"source_list_sha256":s,"superseded_at":t,"record":json.loads(p)} for v,e,s,t,p in db.execute("SELECT version,evidence_sha256,source_list_sha256,superseded_at,payload FROM publication_versions WHERE partition_key=? ORDER BY version DESC",(partition_key,))]


def publication(partition_key):
    with connect() as db:
        row=db.execute("SELECT payload,evidence_sha256,source_list_sha256,active,version FROM publications WHERE partition_key=?",(partition_key,)).fetchone()
        if not row: raise DomainError("NOT_FOUND","交付分区不存在",404)
        return {"partition_key":partition_key,"active":bool(row[3]),"version":row[4],"evidence_sha256":row[1],"source_list_sha256":row[2],"record":json.loads(row[0]),"superseded":_publication_rows(db,partition_key)}


def publications():
    with connect() as db:
        return [{"partition_key":k,"decision":json.loads(p)["decision"],"active":bool(a),"version":v,"evidence_sha256":e,"source_list_sha256":s} for k,p,e,s,a,v in db.execute("SELECT partition_key,payload,evidence_sha256,source_list_sha256,active,version FROM publications ORDER BY partition_key")]


def _verify(record):
    from app.modules.m8_deliveries.rules import verify_record
    ok,problems=verify_record(record)
    if not ok: raise DomainError("EVIDENCE_MISMATCH","证据与来源清单不一致："+"；".join(problems))


def _archive_current(db,key,row,superseded_at):
    db.execute("INSERT OR REPLACE INTO publication_versions(partition_key,version,payload,evidence_sha256,source_list_sha256,superseded_at) VALUES (?,?,?,?,?,?)",(key,row[3],row[0],row[1],row[2],superseded_at))


def _write_active(db,key,payload,evidence_sha256,source_list_sha256,version):
    db.execute("INSERT OR REPLACE INTO publications(partition_key,payload,evidence_sha256,source_list_sha256,active,version) VALUES (?,?,?,?,1,?)",(key,payload,evidence_sha256,source_list_sha256,version))


def publish(record):
    """发布一份交付分区。

    - 只接受结论为可发布的记录（待核/不可发布不落发布记录）；
    - 重跑同一交付分区（同一幂等键）不新增发布记录，返回已有版本并标记 reused；
    - 新依据替换旧版时，旧版连同其依据写入 publication_versions 保留；
    - 替换在单个事务内完成，失败整体回滚，旧版仍为生效记录。
    """
    from app.modules.m8_deliveries.rules import PUBLISHABLE
    if record.get("decision") != PUBLISHABLE:
        raise DomainError("NOT_PUBLISHABLE", "只有可发布的交付分区才能发布")
    key=record["partition_key"]
    _verify(record)
    idem=record["idempotency"]
    payload=json.dumps(record,ensure_ascii=False,sort_keys=True)
    with connect() as db:
        row=db.execute("SELECT payload,evidence_sha256,source_list_sha256,version,active FROM publications WHERE partition_key=?",(key,)).fetchone()
        if row and json.loads(row[0]).get("idempotency")==idem and row[1]==record["evidence_sha256"]:
            return {"partition_key":key,"version":row[3],"active":bool(row[4]),"evidence_sha256":row[1],"source_list_sha256":row[2],"record":json.loads(row[0]),"superseded":_publication_rows(db,key),"reused":True}
        db.execute("BEGIN IMMEDIATE")
        try:
            if row:
                _archive_current(db,key,row,record["evaluated_at"])
                version=row[3]+1
            else:
                version=1
            _write_active(db,key,payload,record["evidence_sha256"],record["source_list_sha256"],version)
        except Exception as error:
            db.rollback()
            raise DomainError("PUBLISH_FAILED",f"发布失败，旧版记录与依据已保留：{error}")
        db.commit()
    return {**publication(key),"reused":False}


def keep_pending(record):
    """记录待核判定，不产生发布。已发布版本保持不变。"""
    key=record["partition_key"]
    with connect() as db:
        row=db.execute("SELECT version FROM publications WHERE partition_key=?",(key,)).fetchone()
    return {"partition_key":key,"decision":record["decision"],"code":record["code"],"reason":record["reason"],"published":False,"active_version":row[0] if row else 0,"evidence_sha256":record["evidence_sha256"],"source_list_sha256":record["source_list_sha256"],"record":record}
