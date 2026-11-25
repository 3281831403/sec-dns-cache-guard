"""递归解析缓存守卫的唯一实现契约。

本模块是仓库中唯一的实现文件，实现 8 个公开函数。实现不联网、不读取
随机数、不引入外部依赖（仅使用标准库）。所有报文、区域、策略与缓存都
由调用方注入，测试只做纯内存计算。

核心安全边界是权威区：一条记录只有在其 owner 名称属于当前权威区，并且
没有落在任何委托点之下时，才可以进入缓存或参与别名链。名称比较必须按
标签边界并忽略 DNS 大小写，不能使用裸后缀比较。附加记录与别名目标都必须
逐条、逐跳执行同一套判定。
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Mapping, MutableMapping, Sequence
from typing import Any

__all__ = [
    "parse_message",
    "in_bailiwick",
    "filter_records",
    "normalize_name",
    "clamp_ttl",
    "resolve_chain",
    "cache_put",
    "cache_batch",
]

_TYPE_MNEMONICS = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    257: "CAA",
}

_MAX_COMPRESSION_POINTERS = 127
_MAX_NAME_OCTETS = 255


def normalize_name(name: str) -> str:
    """归一化 DNS 名称，使同一名称的大小写与根点变体得到同一字符串。

    规则：

    - 只把未转义的 ASCII 字母转小写；非 ASCII 字符保持不变。
    - 去掉一个未转义的末尾根点；单独的根点归一为空字符串。
    - 反斜杠转义必须原样保留，绝不把转义序列解码成它表示的字面字符。
      因此反斜杠加点的单个标签与真正的标签分隔点不是同一个名称，归一
      后也不能相等。
    - 不合并连续点，不删除中间点，不做 IDNA 转换，不添加根点。
    - 非字符串或 None 抛出 ValueError。
    """
    if not isinstance(name, str):
        raise ValueError("name must be a string")

    out: list[str] = []
    escaped = False
    for ch in name:
        if escaped:
            # 转义序列中的字符原样保留，不参与小写转换。
            out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            out.append(ch)
            escaped = True
            continue
        if "A" <= ch <= "Z":
            out.append(chr(ord(ch) + 32))
        else:
            out.append(ch)

    result = "".join(out)

    # 仅剥掉一个“未转义”的末尾根点：数点前连续反斜杠的奇偶即可判断。
    if result.endswith("."):
        backslashes = 0
        idx = len(result) - 2
        while idx >= 0 and result[idx] == "\\":
            backslashes += 1
            idx -= 1
        if backslashes % 2 == 0:
            result = result[:-1]

    return result


def _split_labels(normalized: str) -> list[str]:
    """把已归一化的名称按未转义的点拆成标签（根名拆为单个空标签）。"""
    labels: list[str] = []
    current: list[str] = []
    escaped = False
    for ch in normalized:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\":
            current.append(ch)
            escaped = True
            continue
        if ch == ".":
            labels.append("".join(current))
            current = []
        else:
            current.append(ch)
    labels.append("".join(current))
    return labels


def _is_same_or_below(name_normalized: str, ancestor_normalized: str) -> bool:
    """标签边界判定：名称是否等于祖先或位于祖先之下（两侧均已归一化）。"""
    if ancestor_normalized == "":
        # 根区原点覆盖所有名称。
        return True
    name_labels = _split_labels(name_normalized)
    ancestor_labels = _split_labels(ancestor_normalized)
    if len(name_labels) < len(ancestor_labels):
        return False
    return name_labels[-len(ancestor_labels):] == ancestor_labels


def in_bailiwick(name: str, zone: Mapping[str, Any]) -> bool:
    """判断名称是否位于 zone 的权威区内。

    zone 含 origin 与 delegations 两个键。origin 是区原点，delegations
    是本区向下委托的子区序列。判定规则：

    - 两边先调用 normalize_name，比较忽略 DNS 大小写与末尾根点。
    - 名称必须等于 origin，或位于 origin 之下，并且在标签边界上结束。
      evil-example.com 绝不能因为字符串以 example.com 结尾而被接受。
    - 名称等于或位于任一 delegation 之下时，已经跨越委托点，不属于
      本区，返回 False；委托点自身也返回 False。
    - 根区原点归一为空字符串，覆盖所有名称，但委托点仍然切断。
    - 空名称、畸形 zone、非字符串输入一律返回 False，不抛异常。
    """
    try:
        if not isinstance(name, str) or name == "":
            return False
        if not isinstance(zone, Mapping):
            return False
        origin = zone.get("origin")
        if not isinstance(origin, str) or origin == "":
            return False

        target = normalize_name(name)
        origin_norm = normalize_name(origin)

        if not _is_same_or_below(target, origin_norm):
            return False

        delegations = zone.get("delegations") or ()
        for delegation in delegations:
            if not isinstance(delegation, str) or delegation == "":
                continue
            delegation_norm = normalize_name(delegation)
            if _is_same_or_below(target, delegation_norm):
                # 委托点自身及其下方都不属于本区。
                return False
        return True
    except Exception:
        return False


def filter_records(
    message: Mapping[str, Any],
    zone: Mapping[str, Any],
) -> dict[str, Any]:
    """丢弃越权资源记录，保留区内答案，不修改输入报文。

    返回新的 dict，保留 message 的 id、flags、questions、answers、
    authorities、additionals 六个键，并增加 dropped。questions 原样
    保留。answers、authorities、additionals 中只保留 owner 名称通过
    in_bailiwick 的记录；其余记录被丢弃。dropped 是三段被丢弃记录的总数。

    本函数按 owner 名称过滤，不展开 CNAME 目标，也不根据记录类型做
    额外放行。缺失的区段按空列表处理；输入不得被原地修改。
    """
    filtered: dict[str, Any] = {
        "id": message.get("id"),
        "flags": message.get("flags"),
        "questions": message.get("questions", []),
    }
    dropped = 0
    for section in ("answers", "authorities", "additionals"):
        kept: list[Any] = []
        for record in message.get(section, []) or []:
            owner = record.get("name") if isinstance(record, Mapping) else None
            if in_bailiwick(owner, zone):
                kept.append(record)
            else:
                # 缺陷 1 修复：附加记录与答案、权威记录执行同一套过滤，
                # 任意域的记录一律拒绝进入缓存路径。
                dropped += 1
        filtered[section] = kept
    filtered["dropped"] = dropped
    return filtered


def clamp_ttl(ttl: int, policy: Mapping[str, Any]) -> int:
    """按 policy 的 min_ttl 与 max_ttl 钳制 TTL，返回整数。

    低于 min_ttl 取 min_ttl，高于 max_ttl 取 max_ttl，区间内原样返回。
    零和负数必须落到 min_ttl，不得被解释为永久缓存或跳过缓存。边界值
    本身不变。policy 必须同时提供两个整数边界，且 min_ttl 不得大于
    max_ttl；不满足时抛出 ValueError。
    """
    if not isinstance(policy, Mapping):
        raise ValueError("policy must be a mapping")
    min_ttl = policy.get("min_ttl")
    max_ttl = policy.get("max_ttl")
    # bool 是 int 的子类，但它不是合法的 TTL 边界。
    if (
        not isinstance(min_ttl, int)
        or isinstance(min_ttl, bool)
        or not isinstance(max_ttl, int)
        or isinstance(max_ttl, bool)
    ):
        raise ValueError("min_ttl and max_ttl must be integers")
    if min_ttl > max_ttl:
        raise ValueError("min_ttl must not exceed max_ttl")

    # 缺陷 6 修复：下限同样强制钳制，零/负 TTL 落到 min_ttl。
    if ttl < min_ttl:
        return min_ttl
    if ttl > max_ttl:
        return max_ttl
    return ttl


def _read_wire_name(buf: bytes, offset: int) -> tuple[str, int]:
    """从 wire 报文读取一个名称，支持压缩指针并拒绝指针环/越界。

    返回 (带根点的原始大小写名称, 名称字段在调用方流中的结束偏移)。
    """
    labels: list[str] = []
    seen_pointers: set[int] = set()
    pos = offset
    jumped = False
    stream_end = offset
    pointer_count = 0
    name_octets = 0

    while True:
        if pos < 0 or pos >= len(buf):
            raise ValueError("name read out of bounds")
        length = buf[pos]
        if length == 0:
            if not jumped:
                stream_end = pos + 1
            break
        kind = length & 0xC0
        if kind == 0xC0:
            # 压缩指针：两字节，低 14 位是目标偏移。
            if pos + 1 >= len(buf):
                raise ValueError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | buf[pos + 1]
            if target in seen_pointers:
                raise ValueError("compression pointer loop")
            if target >= len(buf):
                raise ValueError("compression pointer out of bounds")
            if not jumped:
                stream_end = pos + 2
            seen_pointers.add(target)
            pointer_count += 1
            if pointer_count > _MAX_COMPRESSION_POINTERS:
                raise ValueError("too many compression pointers")
            pos = target
            jumped = True
            continue
        if kind != 0:
            # 0x40/0x80 是保留标签类型，合法报文不会出现。
            raise ValueError("reserved label type")
        pos += 1
        if pos + length > len(buf):
            raise ValueError("label exceeds message bounds")
        if name_octets + length + 1 > _MAX_NAME_OCTETS:
            raise ValueError("name too long")
        try:
            labels.append(buf[pos:pos + length].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII wire label") from exc
        name_octets += length + 1
        pos += length

    return ".".join(labels) + ".", stream_end


def _type_mnemonic(rtype: int) -> str:
    return _TYPE_MNEMONICS.get(rtype, f"TYPE{rtype}")


def _read_resource_record(
    buf: bytes, offset: int
) -> tuple[dict[str, Any], int]:
    name, offset = _read_wire_name(buf, offset)
    if offset + 10 > len(buf):
        raise ValueError("truncated resource record")
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[offset:offset + 10])
    offset += 10
    if offset + rdlen > len(buf):
        raise ValueError("rdata exceeds message bounds")
    rdata = buf[offset:offset + rdlen]
    rdata_start = offset
    offset += rdlen

    data: Any = None
    target: Any = None
    if rtype == 1:  # A
        if rdlen != 4:
            raise ValueError("malformed A record")
        data = ".".join(str(octet) for octet in rdata)
    elif rtype == 28:  # AAAA
        if rdlen != 16:
            raise ValueError("malformed AAAA record")
        data = str(ipaddress.IPv6Address(rdata))
    elif rtype in (5, 2):  # CNAME、NS，rdata 是名称（同样允许压缩指针）
        target, _ = _read_wire_name(buf, rdata_start)
    else:
        data = rdata

    return (
        {
            "name": name,
            "type": _type_mnemonic(rtype),
            "ttl": ttl,
            "class": rclass,
            "data": data,
            "target": target,
        },
        offset,
    )


def parse_message(raw: bytes) -> dict[str, Any]:
    """解析 DNS wire 报文，返回问题、答案、权威与附加四个区。

    输入是标准 DNS 报文：12 字节网络序头部，随后是 QDCOUNT 个问题、
    ANCOUNT 个答案、NSCOUNT 个权威记录与 ARCOUNT 个附加记录。名称字段
    必须支持 DNS 压缩指针，并禁止指针环或越界读取。畸形报文抛出
    ValueError。

    返回且仅返回以下六个键：

    - id：报文标识，整数。
    - flags：头部标志，整数。
    - questions：问题列表，每项含 name、type、class。
    - answers：答案记录列表。
    - authorities：权威记录列表。
    - additionals：附加记录列表。

    问题与资源记录的 name 保留报文中的原始大小写，并以根点结尾。资源
    记录含 name、type、ttl、class、data、target 六个键。type 是助记符，
    至少覆盖 A、AAAA、CNAME、NS、SOA、PTR、MX、TXT、SRV、CAA，未知
    类型为 TYPE 加十进制数字；class 保留为整数。A 记录的 data 是点分
    十进制字符串；AAAA 记录的 data 是小写压缩形式字符串；CNAME 与 NS
    记录的 target 是名称；其余记录的 data 是原始 rdata bytes。不适用于
    某条记录的字段为 None。不得把附加区记录悄悄并入答案区。
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 12:
        raise ValueError("malformed DNS message")
    raw = bytes(raw)
    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        ">HHHHHH", raw[:12]
    )

    offset = 12
    questions: list[dict[str, Any]] = []
    for _ in range(qdcount):
        qname, offset = _read_wire_name(raw, offset)
        if offset + 4 > len(raw):
            raise ValueError("truncated question")
        qtype, qclass = struct.unpack(">HH", raw[offset:offset + 4])
        offset += 4
        questions.append(
            {"name": qname, "type": _type_mnemonic(qtype), "class": qclass}
        )

    sections: dict[str, list[dict[str, Any]]] = {}
    for key, count in (
        ("answers", ancount),
        ("authorities", nscount),
        ("additionals", arcount),
    ):
        records: list[dict[str, Any]] = []
        for _ in range(count):
            record, offset = _read_resource_record(raw, offset)
            records.append(record)
        sections[key] = records

    return {
        "id": msg_id,
        "flags": flags,
        "questions": questions,
        "answers": sections["answers"],
        "authorities": sections["authorities"],
        "additionals": sections["additionals"],
    }


def _normalized_or_empty(value: Any) -> str:
    return normalize_name(value) if isinstance(value, str) else ""


def resolve_chain(
    message: Mapping[str, Any],
    zone: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    """从第一个问题名称开始逐跳解析 CNAME 链。

    返回 dict，包含 ok、name、chain、record、ttl、error 六个键。name 是
    起点名称的归一化形式。chain 是归一化名称元组，按访问顺序包含起点
    与每一个 CNAME 目标。

    安全规则：

    - 起点、每个 CNAME 记录的 owner、每个 CNAME 目标、终点记录 owner
      都必须通过 in_bailiwick；任何一跳越权立即失败，不得继续使用该跳
      之后看似合法的记录。
    - 每一跳只接受符合当前名称的 CNAME；重复访问同一归一名称视为环，
      立即失败，不能靠递归深度或超时兜底。
    - 终点只接受符合当前名称的 A 或 AAAA 记录；找不到终点为
      missing_answer。
    - ttl 是终点记录 TTL 经 clamp_ttl 钳制后的整数；失败时为 0。
    - 失败时 ok 为 False，record 为 None，error 为 out_of_bailiwick、
      loop 或 missing_answer 之一。成功时 ok 为 True，error 为 None。

    本函数不写缓存、不修改输入，也不检查附加区中与当前名称无关的记录。
    """
    questions = message.get("questions") or []
    if questions and isinstance(questions[0], Mapping):
        start = _normalized_or_empty(questions[0].get("name"))
    else:
        start = ""
    answers = message.get("answers") or []
    chain: list[str] = [start]

    def failure(error: str) -> dict[str, Any]:
        return {
            "ok": False,
            "name": start,
            "chain": tuple(chain),
            "record": None,
            "ttl": 0,
            "error": error,
        }

    # 起点本身必须在权威区内。
    if not in_bailiwick(start, zone):
        return failure("out_of_bailiwick")

    visited = {start}
    current = start
    while True:
        cname_record = None
        for record in answers:
            if not isinstance(record, Mapping):
                continue
            if record.get("type") != "CNAME":
                continue
            if _normalized_or_empty(record.get("name")) == current:
                cname_record = record
                break

        if cname_record is not None:
            # 缺陷 7 修复：逐跳校验 owner 与目标，任一越权立即失败。
            if not in_bailiwick(cname_record.get("name"), zone):
                return failure("out_of_bailiwick")
            raw_target = cname_record.get("target")
            if not isinstance(raw_target, str):
                return failure("out_of_bailiwick")
            target = normalize_name(raw_target)
            if not in_bailiwick(target, zone):
                return failure("out_of_bailiwick")
            # 缺陷 8 修复：重复访问同一归一名称即环，立即失败。
            if target in visited:
                return failure("loop")
            visited.add(target)
            chain.append(target)
            current = target
            continue

        # 没有下一跳 CNAME，当前名称必须能落到 A/AAAA 终点。
        terminal = None
        for record in answers:
            if not isinstance(record, Mapping):
                continue
            if record.get("type") not in ("A", "AAAA"):
                continue
            if _normalized_or_empty(record.get("name")) == current:
                terminal = record
                break

        if terminal is None:
            return failure("missing_answer")
        if not in_bailiwick(terminal.get("name"), zone):
            return failure("out_of_bailiwick")

        return {
            "ok": True,
            "name": start,
            "chain": tuple(chain),
            "record": terminal,
            "ttl": clamp_ttl(terminal.get("ttl", 0), policy),
            "error": None,
        }


def cache_put(
    store: MutableMapping[str, Any],
    key: str,
    value: Any,
    now: int,
    ttl: int,
) -> dict[str, Any]:
    """把一条解析结果写入缓存，返回写入的条目。

    key 先经 normalize_name 归一，store 只使用归一后的字符串作为键；同一
    名称的大小写变体因此命中同一项，后写覆盖前写。条目是 dict，包含
    key、value、stored_at、expires_at、ttl 五个键，expires_at 等于 now
    加 ttl。store 被原地修改，返回的条目就是 store 中保存的对象。ttl
    由调用方负责先钳制；本函数不再读取 policy。
    """
    # 缺陷 9 修复：缓存键一律归一化，大小写变体不再产生多份缓存。
    normalized_key = normalize_name(key)
    entry = {
        "key": normalized_key,
        "value": value,
        "stored_at": now,
        "expires_at": now + ttl,
        "ttl": ttl,
    }
    store[normalized_key] = entry
    return entry


def cache_batch(
    queries: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
    now: int,
) -> dict[str, Any]:
    """批量独立解析查询，按归一名称读写缓存。

    queries 中每项含 message 与 zone 两个键。policy 含 min_ttl、max_ttl，
    并可含 store；缺省 store 时本次调用新建空 dict，不得在调用之间共享。

    返回 dict，包含 results 与 store。results 与 queries 顺序一致，每项
    含 name、ok、answer、ttl、cache_hit、error：

    - name 是第一个问题名称的归一化形式。
    - 若 store 中存在同名归一键且 expires_at 大于 now，直接返回条目
      value，cache_hit 为 True；不得读取本条 message 的答案来覆盖缓存。
    - 否则调用 resolve_chain。成功时按钳制后的 TTL 调用 cache_put，返回
      解析记录，cache_hit 为 False；失败时不写缓存，answer 为 None。
    - 每个查询只使用自己的 message 与 zone，不得复用上一查询的游标、
      区段下标或答案。不同归一名称之间绝不互相命中。

    缺失问题、缺失区段或畸形查询按其自身错误处理，不能影响其他查询的
    结果。函数返回本次实际使用的 store，便于调用方检查缓存内容。
    """
    provided_store = policy.get("store") if isinstance(policy, Mapping) else None
    if isinstance(provided_store, MutableMapping):
        store = provided_store
    else:
        store = {}

    results: list[dict[str, Any]] = []
    for query in queries or []:
        name = ""
        try:
            message = query.get("message", {}) if isinstance(query, Mapping) else {}
            zone = query.get("zone", {}) if isinstance(query, Mapping) else {}
            questions = message.get("questions") or []
            if questions and isinstance(questions[0], Mapping):
                name = _normalized_or_empty(questions[0].get("name"))

            # 缺陷 10 修复：每次查询只按自己的归一名称查缓存，不存在
            # 跨查询复用的游标；不同名称之间不可能互相命中。
            entry = store.get(name)
            if isinstance(entry, Mapping) and entry.get("expires_at", 0) > now:
                results.append(
                    {
                        "name": name,
                        "ok": True,
                        "answer": entry.get("value"),
                        "ttl": entry.get("ttl", 0),
                        "cache_hit": True,
                        "error": None,
                    }
                )
                continue

            resolved = resolve_chain(message, zone, policy)
            if resolved["ok"]:
                ttl = resolved["ttl"]
                record = cache_put(store, name, resolved["record"], now, ttl)
                results.append(
                    {
                        "name": name,
                        "ok": True,
                        "answer": record["value"],
                        "ttl": ttl,
                        "cache_hit": False,
                        "error": None,
                    }
                )
            else:
                # 失败不写缓存。
                results.append(
                    {
                        "name": name,
                        "ok": False,
                        "answer": None,
                        "ttl": 0,
                        "cache_hit": False,
                        "error": resolved["error"],
                    }
                )
        except Exception:
            # 畸形查询只影响它自己，绝不波及其余查询。
            results.append(
                {
                    "name": name,
                    "ok": False,
                    "answer": None,
                    "ttl": 0,
                    "cache_hit": False,
                    "error": "missing_answer",
                }
            )

    return {"results": results, "store": store}
