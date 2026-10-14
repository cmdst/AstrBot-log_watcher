"""log_watcher 插件包。

模块划分（运行时入口 main.py；其余模块不导入 astrbot，可离线单测）：
- models.py     数据契约：Severity/Route/LogBlock/ThreatVerdict/RemediationRun/SendPlan；
- log_reader.py 解析与增量读取：记录头判定、等级解析、片段合并、摘录切片、tail 读取；
- detect.py     检测层：自身日志屏蔽、指纹、本地保守分级、通知闸门（去重/预算/静默/突发/摘要）；
- deliver.py    投递层：通道能力表、段型选择、分片、退避策略、降级与聚合渲染；
- store.py      持久化：原子写、tail 进度、计数器、待发重试队列、磁盘治理；
- main.py       Star 入口：编排扫描→分级→闸门→投递→重试→落盘，并留出 classify/remediate 集成点。

测试：`python -m pytest tests -q`（纯逻辑、离线、不需要 astrbot）。
"""
