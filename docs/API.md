# 接口

模块GET使用仓内样例，模块POST可传csv或rows与context，直接计算当前规则。/api/runs使用完整流水线并原子保存。每个阶段返回rows、quarantine、metrics；后续阶段还返回累计隔离。/api/upload接收multipart文件file。/api/runs/<id>/archive只导出一份带清单与证据的CSV。

/api/deliveries GET|POST逐份返回交付分区判定，字段含decision（可发布/待核/不可发布）、reason、sources、source_list_sha256、basis、reconciliation、rows。POST可带`partitions`声明来源清单，缺行或未覆盖全部来源行则为待核；声明同一来源行属于两个分区返回422。source_list_sha256、basis.sources_sha256、reconciliation.sources_sha256三者一致，evidence_sha256覆盖三者与证据行。

/api/deliveries/publish只发布可发布分区，待核与不可发布只返回结论不落发布记录；重复发布返回reused=true且版本不变。发布记录含active版本与被替换历史。证据摘要与来源清单不一致时拒绝发布或导出（EVIDENCE_MISMATCH）。/api/deliveries/record/<partition_key>/archive仅在复核通过后输出CSV。
