"""对照布局声明、语句摘要与发布信息，静态审计各读取路径的边界约束。

仅读取本地合成资料；不连接设备、不构造或发送报文。结论只依据材料显式给出
的字段，缺少的字段逐条记为缺失依据，不做缺省推断。

每条发现包含：
  severity   发现类别（supported 之外均属待处理）
  node       合成节点编号（检查 C*、读取 R*、发布记录 id）
  code       机器可读的发现编号
  condition  该发现适用的条件（变体、布局或版本）
  boundary   需要验证的安全边界
  detail     依据说明

判定规则（与资料给出的提示一致）：
  * 检查的 bounds 必须与读取的缓冲区对应；whole-frame 不能替代子段界限。
  * 读取的 length_unit 必须与检查的 offset_unit 一致，变量与单位都一致才算覆盖。
  * 存在长度比较不等于覆盖全部后续读取，proof 字段必须显式完整。
  * 检查的 present_in 未包含的变体，不能认定该变体受保护。
  * 布局只证明它实际声明的范围；整段可读或 public_max_bytes 不能替代子段上限。
  * 发布记录须证明实际启用、对应变体的正常布局及其正常读取结果。
  * 缺少调用关系（path_entries）、运行版本或发布依据时，指出缺少的具体依据。

评审可用 --records 指向更正后的语句摘要目录（同样的三个来源），重新核对
哪些约束已经保护各读取路径。

用法：
    python3 records_audit.py                     # 输出 JSON 报告
    python3 records_audit.py --records 目录
    python3 records_audit.py --summary           # 输出人工阅读的摘要

退出码：0 全部核验通过；2 存在待验证/待修项；资料格式错误时以 argparse 报错。
"""
import argparse
from collections import namedtuple
import json
from pathlib import Path
import sys

# 与 records_view 共用同一套来源加载与分页规则。
from records_view import load_sources

# 发现类别按优先级排列，数值越小越应优先处理。
SEVERITY_ORDER = {
    "unsupported": 0,        # 材料无法支撑该约束
    "mismatch": 1,           # 声明之间不一致
    "incomplete": 2,         # 覆盖范围不完整
    "unverified": 3,         # 缺少必要依据
    "not-actual": 4,         # 不适用于实际发布
    "supported": 5,          # 已由材料核对
}
OPEN_SEVERITIES = set(SEVERITY_ORDER) - {"supported"}
REQUIRED_SOURCES = {"layouts", "reads", "releases"}

Finding = namedtuple("Finding", "severity node code condition boundary detail")


def finding(severity, code, condition, boundary, detail="", node=None):
    return Finding(severity, node, code, condition, boundary, detail)


def _sort_key(item):
    return (SEVERITY_ORDER[item.severity], item.code, item.condition, item.node or "")


def status_of(findings):
    return "open" if any(item.severity in OPEN_SEVERITIES for item in findings) else "supported"


def _findings_json(findings):
    return [item._asdict() for item in sorted(findings, key=_sort_key)]


# --- 资料索引 ---------------------------------------------------------------

def is_check(row):
    return "uses_check" not in row and ("bounds" in row or "offset_unit" in row)


def check_index(reads):
    """检查按 node 与 id 双重索引；读取的 uses_check 通常引用 node。"""
    index = {}
    for row in reads:
        if not is_check(row):
            continue
        for key in (row.get("node"), row.get("id")):
            if isinstance(key, str) and key:
                index[key] = row
    return index


def layout_index(layouts):
    index = {}
    for row in layouts:
        for key in (row.get("id"), row.get("kind")):
            if isinstance(key, str) and key:
                index[key] = row
    return index


def candidate_layouts(variant, layouts):
    """按 kind/id 找到与功能组合同名、但未经发布记录确认的布局。"""
    seen, out = set(), []
    for row in layouts.values():
        if variant in (row.get("id"), row.get("kind")) and id(row) not in seen:
            seen.add(id(row))
            out.append(row)
    return out


# --- 布局能证明的范围 -------------------------------------------------------

def segment_bound(layout, name):
    """该缓冲区名下的独立上限；public_max_bytes 只作为整段缓冲的上限。"""
    segmax = layout.get("segment_max_bytes") or {}
    if name in segmax:
        return segmax[name]
    whole = layout.get("overall_buffer") or "frame"
    if name == whole:
        return layout.get("public_max_bytes")
    return None


def layout_proof(layout):
    """把布局能证明与不能证明的范围分开列出。"""
    buffers = layout.get("buffers") or {}
    overall = layout.get("overall_buffer")
    unit = layout.get("unit")
    public = layout.get("public_max_bytes")
    segmax = layout.get("segment_max_bytes") or {}

    proves, gaps = [], []
    if buffers:
        proves.append("已声明子段: "
                      + ", ".join(f"{name}={size}" for name, size in sorted(buffers.items())))
    if overall:
        proves.append(f"外层缓冲 {overall}，单位 {unit or '未声明'}")
    if public is not None:
        proves.append(f"public_max_bytes={public}（整段上限）")
    for name, size in sorted(segmax.items()):
        proves.append(f"子段 {name} 上限={size}")
    if not buffers and overall:
        gaps.append("仅有整段声明，未声明任何子段缓冲区")
    elif not buffers:
        gaps.append("未声明任何缓冲区")
    if public is not None:
        gaps.append("public_max_bytes 只约束整段，不能替代逐子段上限")
    for name in sorted(buffers):
        if segment_bound(layout, name) is None:
            gaps.append(f"子段 {name} 无独立上限")
    if overall and segment_bound(layout, overall) is None:
        gaps.append(f"外层缓冲 {overall} 无上限")
    return {"proves": proves, "gaps": gaps}


# --- 单条读取的约束判定 -----------------------------------------------------

def constraint_findings(read, check):
    """判定 bounds / length_unit / proof 是否足以约束这条读取。"""
    out = []
    rid = read.get("node") or read.get("id")
    condition = "所有适用变体"
    buffer_name = read.get("reads")

    if check is None:
        out.append(finding("unsupported", "check-missing", condition,
                           "读取路径不得进入",
                           "uses_check 未解析到任何检查摘要", node=rid))
    else:
        cid = check.get("node") or check.get("id")
        if "version" not in check:
            out.append(finding("unverified", "check-version-missing", condition,
                               "检查所适用的运行版本未知", "检查未给出 version", node=cid))
        elif read.get("version") is not None and check["version"] != read.get("version"):
            out.append(finding("mismatch", "check-version-mismatch", condition,
                               "该检查不适用于此读取的版本",
                               f"检查 version={check['version']}，读取 version={read.get('version')}",
                               node=cid))
        if "present_in" not in check:
            out.append(finding("unverified", "check-presence-unverified", condition,
                               "无法确认该检查位于实际编译组合",
                               "检查未声明 present_in", node=cid))
        if "offset_unit" not in check:
            out.append(finding("unverified", "offset-unit-missing", condition,
                               "偏移检查的单位未知", "检查未给出 offset_unit", node=cid))

        bounds = check.get("bounds")
        if buffer_name is None:
            out.append(finding("unverified", "read-buffer-missing", condition,
                               "读取目标未知", "读取未给出 reads", node=rid))
        elif bounds == buffer_name:
            out.append(finding("supported", "bounds-exact", condition,
                               f"仅约束 {buffer_name} 的子段界限",
                               "bounds 与读取缓冲区一致", node=cid))
        elif bounds == "whole-frame" and buffer_name == "frame":
            out.append(finding("supported", "bounds-exact", condition,
                               "frame 整段界限", "读取整段帧", node=cid))
        elif bounds == "whole-frame":
            out.append(finding("unsupported", "bounds-whole-frame-for-segment",
                               condition, f"{buffer_name} 在整段内缺少独立界限",
                               "整段可读不能替代子段界限", node=cid))
        else:
            out.append(finding("unsupported", "bounds-unknown", condition,
                               "读取路径不得进入",
                               f"bounds={bounds!r} 无法与读取 {buffer_name!r} 对应",
                               node=cid))

        length_unit = read.get("length_unit")
        offset_unit = check.get("offset_unit")
        if length_unit is None:
            out.append(finding("unverified", "length-unit-missing", condition,
                               "比较双方的单位一致性无法核对",
                               "读取未给出 length_unit", node=rid))
        elif offset_unit is None:
            out.append(finding("unverified", "unit-unverified", condition,
                               "比较双方的单位一致性无法核对",
                               "偏移单位缺失，不能因存在比较就认定覆盖", node=cid))
        elif length_unit != offset_unit:
            out.append(finding("unsupported", "unit-mismatch", condition,
                               "该比较不约束读取长度",
                               f"length_unit={length_unit} 与 offset_unit={offset_unit} 不一致",
                               node=cid))
        else:
            out.append(finding("supported", "unit-match", condition,
                               "长度与偏移单位一致，比较可约束读取",
                               f"双方单位均为 {length_unit}", node=cid))

    proof = read.get("proof")
    if proof is None:
        out.append(finding("unverified", "proof-missing", condition,
                           "未证明比较覆盖全部后续读取", "语句摘要未给出 proof", node=rid))
    elif proof == "complete":
        out.append(finding("supported", "proof-complete", condition,
                           "比较覆盖全部后续读取", "proof=complete", node=rid))
    else:
        out.append(finding("incomplete", "proof-incomplete", condition,
                           "未覆盖全部后续读取",
                           f"proof={proof!r}；检查存在不等于覆盖", node=rid))
    return out


def evidence_findings(read):
    """运行版本与调用关系的缺失依据。"""
    rid = read.get("node") or read.get("id")
    out = []
    if "version" not in read:
        out.append(finding("unverified", "read-version-missing", "运行版本",
                           "读取所对应的运行版本未知", "读取未给出 version", node=rid))
    if "path_entries" not in read:
        out.append(finding("unverified", "call-path-missing", "调用关系",
                           "无法确认哪些入口会执行该读取",
                           "读取未给出 path_entries", node=rid))
    return out


# --- 布局与变体判定 ---------------------------------------------------------

def layout_findings(read, layout, variant, release_id, linked):
    """该布局的声明能否约束这条读取。

    linked=False 表示布局并非由发布记录的 normal_layouts 指向，只由 kind/id
    推断，即使字段齐全也不能算已确认。
    """
    out = []
    source = "" if linked else "，布局仅由 kind/id 推断"
    cond = f"variant={variant}, layout={layout.get('id')}{source}"
    node = release_id or layout.get("id")
    buffer_name = read.get("reads")
    length_unit = read.get("length_unit")
    buffers = layout.get("buffers") or {}
    overall = layout.get("overall_buffer")
    unit = layout.get("unit")
    public = layout.get("public_max_bytes")
    declared = set(buffers) | ({overall} if overall else set())

    if buffer_name is None:
        return out
    if buffer_name not in declared:
        out.append(finding("unsupported", "buffer-undeclared", cond,
                           f"{buffer_name} 在该布局中无声明，读取路径不得进入",
                           f"布局仅声明 {sorted(declared)}", node=node))
        return out

    buffer_unit = buffers.get(buffer_name)
    if buffer_unit and length_unit and buffer_unit != length_unit:
        out.append(finding("unsupported", "unit-mismatch-buffer", cond,
                           f"{buffer_name} 的长度单位不一致",
                           f"布局为 {buffer_unit}，读取为 {length_unit}", node=node))
    if unit and buffer_name == overall and length_unit and unit != length_unit:
        out.append(finding("unsupported", "unit-mismatch-layout", cond,
                           "外层长度单位不一致，外层比较不能约束该读取",
                           f"布局 unit={unit}，读取 length_unit={length_unit}", node=node))

    bound = segment_bound(layout, buffer_name)
    if bound is None and buffer_name != overall:
        fallback = (f"仅有 public_max_bytes={public}" if public is not None
                    else "无任何上限声明")
        out.append(finding("unverified", "segment-bound-missing", cond,
                           f"{buffer_name} 无独立子段上限",
                           f"{fallback}，不能替代子段界限", node=node))
    elif bound is None:
        out.append(finding("unverified", "overall-bound-missing", cond,
                           f"外层缓冲 {overall} 无上限",
                           "布局未给出 public_max_bytes 或子段上限", node=node))

    if any(item.severity in OPEN_SEVERITIES for item in out):
        return out

    boundary = f"layout {layout.get('id')} 的 {buffer_name} 上限={bound}"
    detail = f"由发布记录 {release_id} 的正常布局覆盖"
    if not linked:
        out.append(finding("unverified", "layout-not-confirmed", cond,
                           boundary, "布局仅由 kind/id 推断，发布记录未确认", node=node))
    else:
        out.append(finding("supported", "layout-covers-buffer", cond, boundary,
                           detail, node=node))
    return out


def normal_result_findings(release, name, layout):
    """发布记录是否给出该有效布局的正常读取结果。"""
    cond = f"variant={release.get('variant')}, layout={layout.get('id')}"
    results = release.get("normal_read_results")
    node = release.get("id")
    if results is None:
        return [finding("unverified", "normal-read-result-missing", cond,
                        "未证明有效布局在该变体的正常读取结果",
                        "发布记录未给出 normal_read_results", node=node)]
    result = None
    if isinstance(results, dict):
        result = results.get(name, results.get(layout.get("id")))
    if result in ("ok", "observed"):
        return [finding("supported", "normal-read-result", cond,
                        f"layout {layout.get('id')} 正常读取结果已记录",
                        f"结果={result}", node=node)]
    return [finding("unverified", "normal-read-result-missing", cond,
                    f"layout {layout.get('id')} 正常读取结果未给出",
                    f"结果={result!r}", node=node)]


def variant_findings(read, check, entry, releases, layouts):
    """针对一个功能组合核对检查是否在场、发布依据与正常布局。"""
    out = []
    cond = f"variant={entry}"
    version = read.get("version")
    cnode = (check or {}).get("node") or (check or {}).get("id")

    if check is not None and "present_in" in check and entry not in check["present_in"]:
        out.append(finding("unsupported", "check-absent-in-variant", cond,
                           "该变体没有边界检查，读取路径不得进入",
                           f"检查 present_in={check['present_in']} 不含 {entry}",
                           node=cnode))

    matches = [r for r in releases
               if r.get("variant") == entry
               and (version is None or r.get("version") == version)]
    if not matches:
        out.append(finding("unverified", "release-variant-missing", cond,
                           "该变体的实际构建未给出",
                           f"没有 version={version}、variant={entry} 的发布记录",
                           node=entry))
        for layout in candidate_layouts(entry, layouts):
            out.extend(layout_findings(read, layout, entry, None, linked=False))
        return out

    for release in matches:
        rid = release.get("id")
        if "activated" not in release:
            out.append(finding("unverified", "build-inclusion-unproven", cond,
                               "实际使用的构建是否包含该修复未知",
                               f"发布记录 {rid} 未给出 activated", node=rid))
        elif release["activated"] is True:
            out.append(finding("supported", "build-inclusion", cond,
                               "实际构建包含该版本",
                               f"发布记录 {rid} activated=true", node=rid))
        else:
            out.append(finding("not-actual", "build-not-activated", cond,
                               "实际构建不含该修复",
                               f"发布记录 {rid} activated=false", node=rid))

        normal = release.get("normal_layouts")
        if normal is None:
            out.append(finding("unverified", "normal-layouts-missing", cond,
                               "有效布局的正常读取结果无法核对",
                               f"发布记录 {rid} 未给出 normal_layouts", node=rid))
            for layout in candidate_layouts(entry, layouts):
                out.extend(layout_findings(read, layout, entry, rid, linked=False))
            continue
        for name in normal:
            layout = layouts.get(name)
            if layout is None:
                out.append(finding("unverified", "layout-unknown", cond,
                                   "正常布局无法核对",
                                   f"{name!r} 不在布局材料中", node=rid))
                continue
            out.extend(layout_findings(read, layout, entry, rid, linked=True))
            out.extend(normal_result_findings(release, name, layout))
    return out


def infer_variants(read, releases):
    """没有 path_entries 时，只能由版本反推候选变体，并标注为推断。"""
    version = read.get("version")
    return sorted({r.get("variant") for r in releases
                   if version is not None and r.get("version") == version
                   and r.get("variant")})


# --- 读取路径汇总 -----------------------------------------------------------

def audit_read(read, checks, layouts, releases):
    check = checks.get(read.get("uses_check"))
    findings = constraint_findings(read, check)
    findings.extend(evidence_findings(read))

    explicit = read.get("path_entries")
    if explicit is None:
        variants = infer_variants(read, releases)
        inferred = True
    else:
        variants = list(explicit)
        inferred = False

    if not variants:
        findings.append(finding("unverified", "variant-unresolved", "适用变体",
                                "无法确定读取所适用的功能组合",
                                "读取未给出 path_entries，版本也未对应发布记录",
                                node=read.get("node") or read.get("id")))
    for entry in variants:
        findings.extend(variant_findings(read, check, entry, releases, layouts))
        if inferred:
            findings.append(finding("unverified", "variant-inferred", f"variant={entry}",
                                    "适用变体由版本反推，缺少显式调用关系",
                                    "读取未给出 path_entries",
                                    node=read.get("node") or read.get("id")))

    condition = "已确认安全的布局"
    if explicit is not None:
        condition = "path_entries 属于已确认安全布局"
    return {
        "id": read.get("id"),
        "node": read.get("node"),
        "reads": read.get("reads"),
        "uses_check": read.get("uses_check"),
        "version": read.get("version"),
        "length_unit": read.get("length_unit"),
        "offset_unit": (check or {}).get("offset_unit"),
        "path_entries": explicit,
        "variants": variants,
        "condition": condition,
        "status": status_of(findings),
        "findings": _findings_json(findings),
    }


def audit_release(release, reads, layouts):
    out = []
    cond = f"variant={release.get('variant')}"
    rid = release.get("id")
    activated = release.get("activated")
    if "activated" not in release:
        out.append(finding("unverified", "activation-missing", cond,
                           "实际构建是否包含该版本未知",
                           "发布记录未给出 activated", node=rid))
    elif activated is True:
        out.append(finding("supported", "activated", cond,
                           "实际构建包含该版本", "activated=true", node=rid))
    else:
        out.append(finding("not-actual", "not-activated", cond,
                           "该版本不是实际发布", "activated=false", node=rid))

    normal = release.get("normal_layouts")
    if normal is None:
        out.append(finding("unverified", "normal-layouts-missing", cond,
                           "有效布局的正常读取结果无法核对",
                           "发布记录未给出 normal_layouts", node=rid))
    else:
        for name in normal:
            layout = layouts.get(name)
            if layout is None:
                out.append(finding("unverified", "layout-unknown", cond,
                                   "正常布局无法核对",
                                   f"{name!r} 不在布局材料中", node=rid))
            else:
                out.append(finding("supported", "layout-exists", cond,
                                   f"layout {layout.get('id')} 在布局材料中",
                                   "", node=rid))
                out.extend(normal_result_findings(release, name, layout))

    linked = [r for r in reads
              if r.get("version") == release.get("version")
              and release.get("variant") in (r.get("path_entries") or [])]
    if linked:
        out.append(finding("supported", "read-path-linked", cond,
                           "发布记录与读取路径已关联",
                           "读取: " + ", ".join(str(r.get("id")) for r in linked),
                           node=rid))
    else:
        out.append(finding("unverified", "no-read-path-linked", cond,
                           "构建包含修复不等于已保护读取路径",
                           "没有读取通过 path_entries 显式指向该变体", node=rid))

    return {"id": rid, "version": release.get("version"),
            "variant": release.get("variant"), "status": status_of(out),
            "findings": _findings_json(out)}


def audit_variant(name, releases, reads):
    rels = [r for r in releases if r.get("variant") == name]
    activated = [r for r in rels if r.get("activated") is True]
    normal = sorted({layout for r in rels for layout in (r.get("normal_layouts") or [])})
    linked = sorted({r.get("id") for r in reads
                     if name in (r.get("path_entries") or [])})
    missing = []
    if not rels:
        missing.append("release")
    elif not any("activated" in r for r in rels):
        missing.append("activated")
    elif not activated:
        missing.append("activated-build")
    if not normal:
        missing.append("normal_layouts")
    if not linked:
        missing.append("read_path")
    status = "supported" if not missing else "open"
    return {"variant": name,
            "releases": [r.get("id") for r in rels],
            "activated": [r.get("id") for r in activated],
            "normal_layouts": normal,
            "read_paths": linked,
            "status": status,
            "missing": missing}


# --- 汇总 -------------------------------------------------------------------

def audit(sources):
    layouts_rows = sources["layouts"]
    reads_rows = sources["reads"]
    releases = sources["releases"]

    checks = check_index(reads_rows)
    layouts = layout_index(layouts_rows)
    read_rows = [row for row in reads_rows if not is_check(row)]

    read_paths = [audit_read(row, checks, layouts, releases) for row in read_rows]
    release_reports = [audit_release(row, read_rows, layouts) for row in releases]

    variant_names = sorted({r.get("variant") for r in releases if r.get("variant")})
    variants = [audit_variant(name, releases, read_rows) for name in variant_names]

    handoff = []
    for path in read_paths:
        for item in path["findings"]:
            if item["severity"] in OPEN_SEVERITIES:
                handoff.append({"path_id": path["id"], "path_kind": "read",
                                "node": item["node"], "severity": item["severity"],
                                "code": item["code"], "condition": item["condition"],
                                "boundary": item["boundary"]})
    for rel in release_reports:
        for item in rel["findings"]:
            if item["severity"] in OPEN_SEVERITIES:
                handoff.append({"path_id": rel["id"], "path_kind": "release",
                                "node": item["node"], "severity": item["severity"],
                                "code": item["code"], "condition": item["condition"],
                                "boundary": item["boundary"]})
    for var in variants:
        if var["status"] == "open":
            handoff.append({"path_id": var["variant"], "path_kind": "variant",
                            "node": var["variant"], "severity": "unverified",
                            "code": "variant-incomplete",
                            "condition": f"variant={var['variant']}",
                            "boundary": "缺少依据: " + ", ".join(var["missing"])})

    layout_reports = []
    for row in layouts_rows:
        proof = layout_proof(row)
        layout_reports.append({
            "id": row.get("id"), "kind": row.get("kind"),
            "unit": row.get("unit"), "buffers": row.get("buffers", {}),
            "overall_buffer": row.get("overall_buffer"),
            "public_max_bytes": row.get("public_max_bytes"),
            "segment_max_bytes": row.get("segment_max_bytes", {}),
            "proves": proof["proves"], "gaps": proof["gaps"],
        })

    return {"layouts": layout_reports, "read_paths": read_paths,
            "releases": release_reports, "variants": variants, "handoff": handoff}


def format_summary(report):
    lines = ["布局能证明的范围:"]
    for layout in report["layouts"]:
        lines.append(f"  {layout['id']} kind={layout['kind']} unit={layout['unit']}")
        for item in layout["proves"]:
            lines.append(f"    可证明: {item}")
        for item in layout["gaps"]:
            lines.append(f"    未证明: {item}")
    lines.append("读取路径:")
    for path in report["read_paths"]:
        lines.append(f"  {path['id']} node={path['node']} status={path['status']}")
        lines.append(f"    condition: {path['condition']}")
        lines.append(f"    arithmetic: offset_unit={path['offset_unit']} "
                     f"length_unit={path['length_unit']}")
        for item in path["findings"]:
            node = f" node={item['node']}" if item["node"] else ""
            lines.append(f"    [{item['severity']}] {item['code']}{node} "
                         f"({item['condition']}): {item['boundary']}")
    lines.append("发布记录:")
    for rel in report["releases"]:
        lines.append(f"  {rel['id']} version={rel['version']} variant={rel['variant']} "
                     f"status={rel['status']}")
        for item in rel["findings"]:
            lines.append(f"    [{item['severity']}] {item['code']}: {item['boundary']}")
    lines.append("功能组合:")
    for var in report["variants"]:
        lines.append(f"  {var['variant']} status={var['status']} "
                     f"activated={var['activated']} normal={var['normal_layouts']} "
                     f"reads={var['read_paths']} missing={var['missing']}")
    lines.append(f"待办交接 ({len(report['handoff'])}):")
    for item in report["handoff"]:
        lines.append(f"  {item['path_kind']}:{item['path_id']} node={item['node']} "
                     f"[{item['severity']}] {item['code']} ({item['condition']}): "
                     f"{item['boundary']}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--records", type=Path,
                        default=Path(__file__).with_name("records"))
    parser.add_argument("--summary", action="store_true", help="输出人工阅读的摘要")
    args = parser.parse_args()
    try:
        sources = load_sources(args.records)
        missing = REQUIRED_SOURCES - set(sources)
        if missing:
            raise ValueError(f"缺少来源: {', '.join(sorted(missing))}")
        report = audit(sources)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    if args.summary:
        print(format_summary(report))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not report["handoff"] else 2


if __name__ == "__main__":
    sys.exit(main())
