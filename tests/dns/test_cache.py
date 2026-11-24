"""sec-dns-cache-guard 的红灯测试。

共 15 个测试：前 10 个一一对应题面的 10 个缺陷，后 5 个是正向与回归
断言。测试不联网、不使用随机数、不发起真实 DNS 查询；报文由本文件内的
字节构造器生成，其余数据均为纯内存 dict。
"""

from __future__ import annotations

import struct

from engine.dns.cache import (
    cache_batch,
    cache_put,
    clamp_ttl,
    filter_records,
    in_bailiwick,
    normalize_name,
    parse_message,
    resolve_chain,
)

ZONE = {"origin": "example.com.", "delegations": ("sub.example.com.",)}
PARENT_ZONE = {"origin": "com.", "delegations": ("example.com.",)}
TTL_POLICY = {"min_ttl": 30, "max_ttl": 3600}


def _policy(store=None):
    return {
        "min_ttl": 30,
        "max_ttl": 3600,
        "store": {} if store is None else store,
    }


def _rr(name, rtype, ttl=300, data=None, target=None):
    return {
        "name": name,
        "type": rtype,
        "ttl": ttl,
        "class": 1,
        "data": data,
        "target": target,
    }


def _message(qname, answers=(), authorities=(), additionals=()):
    return {
        "id": 1,
        "flags": 0x8180,
        "questions": [{"name": qname, "type": "A", "class": 1}],
        "answers": list(answers),
        "authorities": list(authorities),
        "additionals": list(additionals),
    }


def _wire_name(name):
    if name == ".":
        return b"\x00"
    assert name.endswith(".")
    out = bytearray()
    for label in name[:-1].split("."):
        assert label
        raw = label.encode("ascii")
        assert 0 < len(raw) < 64
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _a(address):
    return bytes(int(part) for part in address.split("."))


def _response(qname, answers, authorities=(), additionals=()):
    """构造压缩指针只指向问题名的 DNS 响应。"""
    parts = [
        struct.pack(
            ">HHHHHH",
            0x2A2A,
            0x8180,
            1,
            len(answers),
            len(authorities),
            len(additionals),
        ),
        _wire_name(qname),
        struct.pack(">HH", 1, 1),
    ]
    for owner, rtype, ttl, rdata in answers:
        parts.extend(
            [owner, struct.pack(">HHIH", rtype, 1, ttl, len(rdata)), rdata]
        )
    for owner, rtype, ttl, rdata in authorities:
        parts.extend(
            [owner, struct.pack(">HHIH", rtype, 1, ttl, len(rdata)), rdata]
        )
    for owner, rtype, ttl, rdata in additionals:
        parts.extend(
            [owner, struct.pack(">HHIH", rtype, 1, ttl, len(rdata)), rdata]
        )
    return b"".join(parts)


# 缺陷 1：附加记录不过滤，任意域的记录被接受。
def test_filter_discards_out_of_zone_additional():
    message = _message(
        "www.example.com.",
        answers=[_rr("www.example.com.", "A", 120, data="192.0.2.10")],
        additionals=[
            _rr("ns1.example.com.", "A", 60, data="192.0.2.53"),
            _rr("bank.example.net.", "A", 60, data="203.0.113.66"),
        ],
    )

    filtered = filter_records(message, ZONE)

    assert [record["name"] for record in filtered["additionals"]] == [
        "ns1.example.com."
    ]
    assert filtered["dropped"] == 1
    assert filtered["answers"][0]["data"] == "192.0.2.10"
    assert len(message["additionals"]) == 2


# 缺陷 2：bailiwick 只比较后缀，evil-example.com 被当作 example.com 区内。
def test_bailiwick_rejects_suffix_lookalike():
    assert in_bailiwick("evil-example.com.", ZONE) is False
    assert in_bailiwick("notexample.com.", ZONE) is False
    assert in_bailiwick("example.com.", ZONE) is True
    assert in_bailiwick("www.example.com.", ZONE) is True


# 缺陷 3：bailiwick 不识别委托点，子区记录被上级接受。
def test_bailiwick_rejects_delegated_subzone():
    assert in_bailiwick("example.com.", PARENT_ZONE) is False
    assert in_bailiwick("www.example.com.", PARENT_ZONE) is False
    assert in_bailiwick("other.com.", PARENT_ZONE) is True


# 缺陷 4：名称归一不去尾点，根区名称多出一层。
def test_normalize_strips_root_dot():
    assert normalize_name("WWW.Example.COM.") == "www.example.com"
    assert normalize_name("example.com") == "example.com"
    assert normalize_name(".") == ""


# 缺陷 5：名称归一把转义标签解码后再比较，语义被改。
def test_normalize_preserves_escaped_labels():
    normalized = normalize_name(r"a\.b.Example.COM.")

    assert normalized == r"a\.b.example.com"
    assert normalized != "a.b.example.com"
    assert normalize_name(r"\046x.Example.") == r"\046x.example"
    assert normalize_name(r"label\..") == r"label\."


# 缺陷 6：TTL 只钳上限不钳下限，零或负 TTL 被当永久。
def test_clamp_rejects_zero_and_negative_ttl():
    assert clamp_ttl(0, TTL_POLICY) == 30
    assert clamp_ttl(-1, TTL_POLICY) == 30
    assert clamp_ttl(29, TTL_POLICY) == 30


# 缺陷 7：别名链不检查每跳是否在区内，跨区跳转被接受。
def test_alias_chain_checks_every_hop():
    good = _message(
        "a.example.com.",
        answers=[
            _rr("a.example.com.", "CNAME", target="b.example.com."),
            _rr("b.example.com.", "CNAME", target="c.example.com."),
            _rr("c.example.com.", "A", 120, data="192.0.2.9"),
        ],
    )

    resolved = resolve_chain(good, ZONE, TTL_POLICY)

    assert resolved["ok"] is True
    assert resolved["name"] == "a.example.com"
    assert resolved["chain"] == (
        "a.example.com",
        "b.example.com",
        "c.example.com",
    )
    assert resolved["record"]["data"] == "192.0.2.9"
    assert resolved["ttl"] == 120
    assert resolved["error"] is None

    bad = _message(
        "a.example.com.",
        answers=[
            _rr("a.example.com.", "CNAME", target="b.example.net."),
            _rr("b.example.net.", "A", 120, data="203.0.113.9"),
        ],
    )

    escaped = resolve_chain(bad, ZONE, TTL_POLICY)

    assert escaped["ok"] is False
    assert escaped["error"] == "out_of_bailiwick"


# 缺陷 8：别名链不检测环，互相指向的两条记录导致死循环。
def test_alias_chain_detects_cycle():
    message = _message(
        "loop1.example.com.",
        answers=[
            _rr("loop1.example.com.", "CNAME", target="loop2.example.com."),
            _rr("loop2.example.com.", "CNAME", target="loop1.example.com."),
        ],
    )

    resolved = resolve_chain(message, ZONE, TTL_POLICY)

    assert resolved["ok"] is False
    assert resolved["error"] == "loop"


# 缺陷 9：缓存键区分大小写，同一名称产生多份缓存。
def test_cache_key_is_case_insensitive():
    store = {}
    first = cache_put(
        store,
        "WWW.Example.COM.",
        {"type": "A", "data": "192.0.2.1"},
        100,
        300,
    )
    second = cache_put(
        store,
        "www.example.com.",
        {"type": "A", "data": "192.0.2.2"},
        200,
        300,
    )

    assert first["key"] == "www.example.com"
    assert len(store) == 1
    assert set(store) == {"www.example.com"}
    assert store["www.example.com"]["value"]["data"] == "192.0.2.2"
    assert second["stored_at"] == 200
    assert second["expires_at"] == 500


# 缺陷 10：批量解析复用缓存游标，第二个查询命中第一个查询的结果。
def test_batch_queries_do_not_share_cursor():
    store = {}
    first = _message(
        "a.example.com.",
        answers=[_rr("a.example.com.", "A", 120, data="192.0.2.1")],
    )
    second = _message(
        "b.example.com.",
        answers=[_rr("b.example.com.", "A", 120, data="192.0.2.2")],
    )

    outcome = cache_batch(
        [
            {"message": first, "zone": ZONE},
            {"message": second, "zone": ZONE},
        ],
        _policy(store),
        1000,
    )

    results = outcome["results"]
    assert [item["name"] for item in results] == [
        "a.example.com",
        "b.example.com",
    ]
    assert [item["answer"]["data"] for item in results] == [
        "192.0.2.1",
        "192.0.2.2",
    ]
    assert [item["cache_hit"] for item in results] == [False, False]
    assert set(outcome["store"]) == {"a.example.com", "b.example.com"}


# 正向 1：区内答案被缓存。
def test_in_zone_answer_is_cached():
    policy = _policy()
    message = _message(
        "www.example.com.",
        answers=[_rr("www.example.com.", "A", 120, data="192.0.2.10")],
    )

    outcome = cache_batch(
        [{"message": message, "zone": ZONE}],
        policy,
        1000,
    )

    result = outcome["results"][0]
    assert result["ok"] is True
    assert result["cache_hit"] is False
    assert result["answer"]["data"] == "192.0.2.10"

    entry = outcome["store"]["www.example.com"]
    assert entry["value"]["data"] == "192.0.2.10"
    assert entry["expires_at"] == 1120


# 正向 2：越权附加记录被丢弃。
def test_out_of_zone_additional_is_dropped():
    raw = _response(
        "www.example.com.",
        answers=[(b"\xc0\x0c", 1, 120, _a("192.0.2.10"))],
        additionals=[
            (_wire_name("ns1.example.com."), 1, 60, _a("192.0.2.53")),
            (_wire_name("bank.example.net."), 1, 60, _a("203.0.113.66")),
            (_wire_name("x.sub.example.com."), 1, 60, _a("203.0.113.77")),
        ],
    )

    parsed = parse_message(raw)
    assert parsed["id"] == 0x2A2A
    assert parsed["questions"][0]["name"] == "www.example.com."
    assert parsed["answers"][0]["name"] == "www.example.com."
    assert parsed["answers"][0]["type"] == "A"
    assert parsed["answers"][0]["data"] == "192.0.2.10"

    filtered = filter_records(parsed, ZONE)

    assert [record["name"] for record in filtered["additionals"]] == [
        "ns1.example.com."
    ]
    assert filtered["dropped"] == 2
    assert len(parsed["additionals"]) == 3


# 正向 3：名称大小写不同命中同一缓存项。
def test_case_variants_hit_same_cache_entry():
    store = {}
    cache_put(
        store,
        "www.example.com.",
        {
            "name": "www.example.com.",
            "type": "A",
            "ttl": 300,
            "class": 1,
            "data": "192.0.2.1",
            "target": None,
        },
        1000,
        300,
    )
    message = _message(
        "WWW.Example.COM.",
        answers=[_rr("WWW.Example.COM.", "A", 300, data="192.0.2.99")],
    )

    outcome = cache_batch(
        [{"message": message, "zone": ZONE}],
        _policy(store),
        1100,
    )

    result = outcome["results"][0]
    assert result["name"] == "www.example.com"
    assert result["cache_hit"] is True
    assert result["answer"]["data"] == "192.0.2.1"
    assert len(outcome["store"]) == 1
    assert set(outcome["store"]) == {"www.example.com"}


# 正向 4：TTL 超上限被钳到上限。
def test_ttl_above_max_is_clamped_to_max():
    assert clamp_ttl(3601, TTL_POLICY) == 3600
    assert clamp_ttl(86400, TTL_POLICY) == 3600
    assert clamp_ttl(3600, TTL_POLICY) == 3600


# 正向 5：两批独立解析与单独解析相同。
def test_batch_results_match_individual_resolution():
    messages = [
        _message(
            "a.example.com.",
            answers=[_rr("a.example.com.", "A", 120, data="192.0.2.11")],
        ),
        _message(
            "b.example.com.",
            answers=[_rr("b.example.com.", "A", 180, data="192.0.2.12")],
        ),
        _message(
            "c.example.com.",
            answers=[_rr("c.example.com.", "A", 240, data="192.0.2.13")],
        ),
    ]
    queries = [{"message": message, "zone": ZONE} for message in messages]

    def summarize(outcome):
        return [
            (
                item["name"],
                item["ok"],
                None if item["answer"] is None else item["answer"]["data"],
                item["ttl"],
                item["cache_hit"],
            )
            for item in outcome["results"]
        ]

    batch_one = summarize(cache_batch(queries, _policy(), 1000))
    batch_two = summarize(cache_batch(queries, _policy(), 1000))

    individual = []
    for query in queries:
        individual.extend(summarize(cache_batch([query], _policy(), 1000)))

    assert batch_one == batch_two
    assert batch_one == individual