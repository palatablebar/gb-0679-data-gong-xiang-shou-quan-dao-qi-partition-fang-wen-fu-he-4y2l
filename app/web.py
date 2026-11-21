from flask import render_template
from app.config import MODULES,TITLE,SHORT
from app.pipeline import execute,load_sample
from app import store
COLUMNS_BY_INDEX=[['event_id', 'principal', 'resource', 'partition', 'access_time', 'observed'], ['event_id', 'principal', 'resource', 'partition'], ['event_id', 'principal', 'resource', 'partition', 'at', 'candidate_count'], ['event_id', 'principal', 'partition', 'rule_evidence', 'effect', 'conflict'], ['event_id', 'principal', 'resource', 'partition', 'effect', 'observed', 'partition_result', 'violation'], ['event_id', 'principal', 'expected', 'reported', 'difference', 'violation', 'status'], ['event_id', 'principal', 'resource', 'partition', 'rule_evidence', 'violation', 'status']]
DELIVERY_COLUMNS=['partition_key', 'partition', 'decision', 'reason', 'source_count', 'authorized_count', 'source_list_sha256']
LABELS={'event_id': '事件号', 'principal': '主体', 'resource': '资源', 'partition': '分区', 'access_time': '访问时刻', 'observed': '执行结果', 'at': '事件 UTC', 'candidate_count': '生效授权数', 'rule_evidence': '命中规则', 'effect': '授权裁决', 'conflict': '规则冲突', 'partition_result': '分区裁决', 'violation': '执行差异', 'expected': '应允许', 'reported': '实允许', 'difference': '差异', 'status': '结论', 'resources': '资源数', 'accepted': '采纳行', 'active_hits': '生效命中', 'grant_versions': '授权数', 'conflicts': '冲突行', 'explicit_denies': '显式拒绝', 'default_denies': '默认拒绝', 'allowed': '应放行', 'blocked': '应拒绝', 'violations': '越权放行', 'false_blocks': '误拦截', 'records': '封存数', 'source_lines': '来源行', 'sha256': '摘要', 'ready': '可封存', 'differences': '差异数',
        'accepted_inputs': '采纳来源行', 'quarantine_inputs': '隔离来源行', 'output_records': '结果记录', 'input': '输入行', 'excluded': '排除行', 'balanced': '行数平衡', 'expected_total': '预期合计', 'reported_total': '申报合计', 'differences': '差异项', 'blank': '空行', 'repeated_headers': '分段表头', 'encoding': '编码', 'duplicate': '重复行', 'quarantine': '隔离行', 'accepted': '采纳行', 'sha256': '校验摘要', 'ready': '可归档',
        'partition_key': '交付分区', 'decision': '发布结论', 'reason': '判定依据', 'source_count': '来源行数', 'authorized_count': '已核准来源', 'source_list_sha256': '来源清单摘要', 'total': '分区数', 'publishable': '可发布', 'pending': '待核', 'blocked': '不可发布', 'source_lists': '来源行合计', 'complete': '来源齐全', 'policy': '判定口径'}
def register_pages(app):
    def page(index,run=None):
        run=run or store.latest() or execute(load_sample("dirty.csv"))
        delivery_view=None;publications=store.publications()
        if index>=len(COLUMNS_BY_INDEX):
            from app.modules.m8_deliveries import rules as delivery_rules
            delivery_view=delivery_rules.evaluate(run)
            active={p["partition_key"]:p for p in publications}
            rows=[]
            for record in delivery_view["deliveries"]:
                stored=active.get(record["partition_key"])
                rows.append({**record,
                             "source_count":record["basis"]["source_count"],
                             "authorized_count":record["basis"]["authorized_count"],
                             "active":bool(stored),"published_version":stored["version"] if stored else 0})
            columns=DELIVERY_COLUMNS;stage={"rows":rows,"metrics":delivery_view["summary"],"cumulative_quarantine":[]}
        else:
            stage=run["stages"][index];rows=stage["rows"];columns=COLUMNS_BY_INDEX[index]
        return render_template(f"m{index+1}.html",title=TITLE,short=SHORT,modules=MODULES,index=index,run=run,stage=stage,rows=rows,columns=columns[:12],history=store.history(),labels=LABELS,delivery_view=delivery_view,publications=publications)
    app.add_url_rule("/",view_func=lambda:page(4))
    for index,(slug,name) in enumerate(MODULES):
        app.add_url_rule("/"+slug,endpoint="page_"+slug,view_func=lambda index=index:page(index))
