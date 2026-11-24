递归解析接了缓存之后，一条附加记录就把不相干域的解析结果换成了攻击者的地址：附加记录不过滤，任意域的记录被接受；bailiwick 判定只比较后缀，evil-example.com 被当作 example.com 区内；bailiwick 不识别委托点，子区记录被上级接受；名称归一不去尾点，根区名称多出一层；名称归一把转义标签解码后再比较，语义被改；TTL 只钳上限不钳下限，零或负 TTL 被当永久；别名链不检查每跳是否在区内，跨区跳转被接受；别名链不检测环，互相指向的两条记录导致死循环；缓存键区分大小写，同一名称产生多份缓存；批量解析复用缓存游标，第二个查询命中第一个查询的结果。engine/dns/cache.py 是核心，tests/dns/test_cache.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

# sec-dns-cache-guard

## 运行方式

在仓库根目录执行：

    python -m pytest tests -q

预期输出为 15 failed，无 error，无 collection error。测试不联网、不使用随机数、不发起真实 DNS 查询，所有 DNS 报文都由测试文件内的字节构造器生成。

自检输出尾部示例：

    15 failed in 0.xxs

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 目录布局

本仓库采用 engine 嵌套布局：

    sec-dns-cache-guard/
      README.md
      conftest.py
      engine/
        __init__.py
        dns/
          __init__.py
          cache.py
      tests/
        dns/
          test_cache.py

engine/dns/cache.py 是唯一实现文件，tests/dns/test_cache.py 是唯一测试入口。engine 与 tests 的 dns 目录镜像对应。仓库根的 conftest.py 只负责把仓库根加入 sys.path，使 from engine.dns.cache import ... 可用。

## tests 约束

tests/dns/test_cache.py 恰好包含 15 个测试，交付后不可修改。实现者只能补全 engine/dns/cache.py 中的 8 个桩，不得通过改测试、删测试、跳过测试、动态生成测试或放宽断言获得通过。实现不得联网、不得读取随机数、不得引入外部依赖。

## 数据契约

本节描述 15 个测试使用的输入输出，实现必须保持下列签名与结构。

### 区域对象

zone 是映射，包含两个键：origin 是权威区原点，delegations 是委托点子区序列。名称比较前先归一。名称必须等于原点或位于原点之下，并且在标签边界上；名称等于或位于任一委托点之下时不属于本区。根区原点为点号，归一后为空字符串，覆盖所有名称。

### parse_message

输入是 DNS wire 格式的 bytes，包含标准 12 字节头部与问题、答案、权威、附加四个区。实现必须处理名称压缩指针，并防止指针环。返回 dict，包含 id、flags、questions、answers、authorities、additionals 六个键。问题记录包含 name、type、class。资源记录包含 name、type、ttl、class、data、target。名称保留报文中的大小写并以根点结尾。type 使用助记符，至少覆盖 A、AAAA、CNAME、NS、SOA、PTR、MX、TXT、SRV、CAA，未知类型用 TYPE 加十进制数字。A 记录的 data 是点分十进制字符串；CNAME 与 NS 记录的 target 是名称；其他记录的 data 是原始 rdata bytes，不适用的字段为 None。

### in_bailiwick 与 filter_records

in_bailiwick 返回名称是否属于 zone 的权威区。filter_records 返回新的报文 dict，保留原本六个键并增加 dropped，不修改输入。questions 原样保留；answers、authorities、additionals 中只有 owner 名称属于 zone 的资源记录被保留，其余丢弃，dropped 是三类被丢弃记录的总数。过滤以记录 owner 为准，不在本阶段展开别名目标。

### normalize_name 与 clamp_ttl

normalize_name 只做名称归一：ASCII 字母转小写，去掉一个未转义的末尾根点，根点归一为空字符串；反斜杠转义按原样保留，绝不把转义标签解码成字面字符。因此 a 反斜杠点 b 形式的标签与 a 点 b 是两个不同名称。clamp_ttl 从 policy 读取 min_ttl 与 max_ttl，低于下限取 min_ttl，高于上限取 max_ttl，零与负数都必须落到 min_ttl，不得视为永久缓存。

### resolve_chain

resolve_chain 从 message 的第一个问题名称开始沿 CNAME 链解析。chain 是已访问名称的归一化元组，包含起点与每一跳目标。每一跳的 owner 和目标都必须 in_bailiwick；任何越权跳立即失败。重复访问同一名称视为环并立即失败。返回 dict，包含 ok、name、chain、record、ttl、error。成功时 record 是终点的 A 或 AAAA 记录，ttl 是经 clamp_ttl 钳制后的值，error 为 None。失败时 record 为 None，ttl 为 0，error 为 out_of_bailiwick、loop 或 missing_answer 之一。

### cache_put 与 cache_batch

cache_put 将 key 归一后写入 store，同一归一名称只有一项；后写覆盖前写。条目是 dict，包含 key、value、stored_at、expires_at、ttl，expires_at 等于 now 加 ttl。函数返回写入的条目，并原地修改 store。

cache_batch 的 queries 是序列，每项包含 message 与 zone。policy 除 min_ttl 与 max_ttl 外可含 store；缺省时本次调用新建空 dict。返回 dict，包含 results 与 store 两个键。results 与 queries 顺序一一对应，每项包含 name、ok、answer、ttl、cache_hit、error。每个查询只读取自己的 message 与 zone，不得共享游标或上一查询的结果。若 store 中存在未过期的同名归一键，直接返回该条目并置 cache_hit 为 True；否则调用 resolve_chain，成功时按钳制后的 TTL 写入缓存并置 cache_hit 为 False。失败查询不写缓存。不同归一名称之间绝不互相命中。

## 15 个测试

缺陷对应：

1. test_filter_discards_out_of_zone_additional
2. test_bailiwick_rejects_suffix_lookalike
3. test_bailiwick_rejects_delegated_subzone
4. test_normalize_strips_root_dot
5. test_normalize_preserves_escaped_labels
6. test_clamp_rejects_zero_and_negative_ttl
7. test_alias_chain_checks_every_hop
8. test_alias_chain_detects_cycle
9. test_cache_key_is_case_insensitive
10. test_batch_queries_do_not_share_cursor

正向与回归：

11. test_in_zone_answer_is_cached
12. test_out_of_zone_additional_is_dropped
13. test_case_variants_hit_same_cache_entry
14. test_ttl_above_max_is_clamped_to_max
15. test_batch_results_match_individual_resolution