"""本地防御性静态审计：固定缓冲区、子段长度与偏移检查的覆盖核对。

只读取本地合成记录（layouts/reads/releases），不连接任何设备，也不构造、
编码或发送测试报文。报告仅使用合成节点编号、适用条件与应验证的安全边界，
不输出任何触发字节。

审计原则：
* 检查存在一处长度比较，并不等于覆盖后续全部读取；比较的变量与单位必须一致。
* 子段（part）的界限不能由整段（whole-frame）可读证明替代。
* 缺少调用关系或运行版本信息时，明确列出缺少的具体依据。
* 发布声明必须能证明实际构建包含修复，且有效布局在对应变体有正常读取结果。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from records_view import load_sources

SOURCE_NAMES = ("layouts", "reads", "releases")

CONDITION_META = {
    "variant": ("变体归属", "F-VARIANT"),
    "check_ref": ("检查引用", "F-CHECK-REF"),
    "check_version": ("版本一致", "F-VERSION"),
    "scope": ("界限范围", "F-SCOPE"),
    "unit": ("比较单位", "F-UNIT"),
    "variable": ("比较变量", "F-VARIABLE"),
    "presence": ("变体编译", "F-PRESENCE"),
    "proof": ("语句证明完整性", "F-PROOF"),
    "call_path": ("调用关系", "F-CALLGRAPH"),
    "layout_resolution": ("布局适用", "F-LAYOUT-MAP"),
    "layout_unit": ("布局计量单位", "F-LAYOUT-UNIT"),
    "outer_length": ("外层长度", "F-OUTER-LENGTH"),
    "fixed_buffer": ("固定缓冲区上限", "F-FIXED-BUFFER"),
    "build": ("构建包含修复", "F-BUILD"),
    "normal_read": ("正常读取结果", "F-NORMAL-READ"),
}

BOUNDARIES = {
    "variant": "读取语句归属于明确的变体路径",
    "check_ref": "读取由存在且已声明的检查约束",
    "check_version": "检查与读取语句属于同一版本",
    "scope": "子段读取的界限由同范围检查给出，整段可读不替代子段界限",
    "unit": "检查比较的变量与读取长度使用同一单位",
    "variable": "检查比较的变量包含读取使用的长度变量",
    "presence": "检查存在于读取路径对应的变体编译产物",
    "proof": "语句摘要完整覆盖该读取",
    "call_path": "读取在执行路径上位于检查之后",
    "layout_resolution": "读取路径对应已确认的布局",
    "layout_unit": "偏移与长度单位与布局的计量单位一致",
    "outer_length": "依赖外层长度的布局由外层长度推导子段上界",
    "fixed_buffer": "读取上界不超过固定缓冲区声明的上限",
    "build": "实际构建包含约束该读取的检查",
    "normal_read": "有效布局在该变体的正常读取结果",
}


def _condition(condition_id, status, detail, basis=None):
    label, code = CONDITION_META[condition_id]
    result = {
        "id": condition_id,
        "label": label,
        "code": code,
        "status": status,
        "boundary": BOUNDARIES[condition_id],
        "detail": detail,
    }
    if basis:
        result["missing_basis"] = basis
    return result


def _layout_unit(layout):
    if not layout:
        return None
    if layout.get("unit"):
        return layout["unit"]
    buffers = layout.get("buffers") or {}
    if isinstance(buffers, dict) and buffers and all(value == "bytes" for value in buffers.values()):
        return "bytes"
    if "public_max_bytes" in layout:
        return "bytes"
    return None


def _match_layout(name, layouts):
    matches = []
    for layout in layouts:
        if layout.get("id") in (name, f"layout-{name}"):
            matches.append(layout)
        elif layout.get("kind") == name or layout.get("name") == name:
            matches.append(layout)
    return matches[0] if matches else None


def resolve_layout(variant, layouts, releases):
    """返回 (布局记录, 依据, 发布记录标识)。"""
    explicit = []
    for release in releases:
        if release.get("variant") != variant:
            continue
        for name in release.get("normal_layouts") or []:
            layout = _match_layout(name, layouts)
            if layout is not None:
                explicit.append((layout, release.get("id")))
    if explicit:
        return explicit[0][0], "release.normal_layouts", explicit[0][1]
    inferred = [layout for layout in layouts if layout.get("kind") == variant]
    if len(inferred) == 1:
        return inferred[0], "layout.kind", None
    return None, None, None


def _release_contains(release, check_id, node):
    for key in ("includes_checks", "checks"):
        values = release.get(key)
        if isinstance(values, list) and (check_id in values or node in values):
            return True
    fixes = release.get("fixes")
    if isinstance(fixes, list) and any(item in (check_id, node) for item in fixes):
        return True
    return release.get("contains_fix") is True


def _normal_read_result(release, layout):
    evidence = release.get("normal_read") or release.get("normal_read_result")
    if evidence is None:
        return None
    if isinstance(evidence, str):
        return "ok" if evidence in ("ok", "pass", "normal") else evidence
    if isinstance(evidence, dict):
        named = evidence.get("layout")
        if named is not None and layout is not None:
            aliases = {layout.get("id"), layout.get("kind"), layout.get("name")}
            aliases.update(release.get("normal_layouts") or [])
            identifier = layout.get("id") or ""
            if identifier.startswith("layout-"):
                aliases.add(identifier[len("layout-"):])
            if named not in aliases:
                return "layout-mismatch"
        if evidence.get("verified") is True:
            return "ok"
        return evidence.get("result")
    return "unrecognized"


def _variants_for(read, releases):
    entries = read.get("path_entries")
    if isinstance(entries, list) and entries:
        return list(entries), "path_entries"
    inferred = sorted({
        release.get("variant") for release in releases
        if release.get("version") == read.get("version") and release.get("variant")
    })
    if inferred:
        return inferred, "release.version"
    return [], None


def _evaluate_path(read, check, variant, variant_basis, layout, layout_basis, releases):
    version = read.get("version")
    node = read.get("node")
    target = read.get("reads")
    read_unit = read.get("length_unit")
    check_id = read.get("uses_check")
    check_unit = check.get("offset_unit") if check else None
    conditions = []

    if variant is None:
        conditions.append(_condition(
            "variant", "unknown",
            f"无法确定读取语句 {read.get('id')} 所属变体：没有 path_entries，同版本也没有发布记录",
            "缺少变体归属（path_entries 或同版本发布记录）"))
    elif variant_basis == "path_entries":
        conditions.append(_condition("variant", "pass", f"语句声明 path_entries 包含 {variant}"))
    else:
        conditions.append(_condition(
            "variant", "unknown",
            f"读取语句 {read.get('id')} 没有 path_entries；{variant} 仅由版本 {version} 的发布记录推断",
            "缺少读取路径到变体的直接声明（path_entries）"))

    if check is None:
        conditions.append(_condition(
            "check_ref", "fail",
            f"uses_check={check_id} 在 reads 中没有对应检查记录",
            "缺少被引用的检查记录"))
    else:
        conditions.append(_condition(
            "check_ref", "pass",
            f"检查 {check_id} 存在（bounds={check.get('bounds')}）"))

    if check is None:
        conditions.append(_condition(
            "check_version", "unknown", "检查记录缺失，无法核对版本", "缺少检查记录的 version"))
    elif check.get("version") == version:
        conditions.append(_condition(
            "check_version", "pass", f"检查 {check_id} 与读取语句同为版本 {version}"))
    else:
        conditions.append(_condition(
            "check_version", "fail",
            f"检查 {check_id} 属于版本 {check.get('version')}，读取语句属于版本 {version}"))

    if check is None:
        conditions.append(_condition(
            "scope", "unknown", "检查记录缺失，无法核对界限范围", "缺少检查的 bounds"))
    elif check.get("bounds") == target:
        conditions.append(_condition(
            "scope", "pass", f"检查 {check_id} 的界限范围 {check.get('bounds')} 与读取目标一致"))
    elif check.get("bounds") is None:
        conditions.append(_condition(
            "scope", "unknown", f"检查 {check_id} 未声明 bounds", "缺少检查的界限范围"))
    else:
        conditions.append(_condition(
            "scope", "fail",
            f"检查 {check_id} 的界限为 {check.get('bounds')}，读取目标是 {target}；"
            "整段可读不能替代子段界限"))

    if check is None or check_unit is None:
        conditions.append(_condition(
            "unit", "unknown", f"检查 {check_id} 未声明 offset_unit，无法核对比较单位",
            "缺少检查的比较单位"))
    elif check_unit == read_unit:
        conditions.append(_condition(
            "unit", "pass", f"检查 {check_id} 与读取均以 {read_unit} 计量"))
    else:
        conditions.append(_condition(
            "unit", "fail",
            f"检查 {check_id} 以 {check_unit} 比较偏移，读取以 {read_unit} 计长度；"
            "单位不同，长度比较不覆盖该读取"))

    if check is None:
        conditions.append(_condition(
            "variable", "unknown", "检查记录缺失，无法核对长度比较变量", "缺少检查的比较变量"))
    else:
        compares = check.get("compares")
        length_unit = check.get("length_unit")
        if isinstance(compares, list) and compares:
            if "length" not in compares:
                conditions.append(_condition(
                    "variable", "fail",
                    f"检查 {check_id} 只比较 {compares}，未包含读取使用的长度变量"))
            elif length_unit is None:
                conditions.append(_condition(
                    "variable", "unknown",
                    f"检查 {check_id} 声明比较 length，但没有给出 length_unit",
                    "缺少检查长度比较的单位"))
            elif length_unit != read_unit:
                conditions.append(_condition(
                    "variable", "fail",
                    f"检查 {check_id} 的长度单位为 {length_unit}，读取为 {read_unit}"))
            else:
                conditions.append(_condition(
                    "variable", "pass",
                    f"检查 {check_id} 比较 offset 与 length，长度单位为 {length_unit}"))
        elif length_unit is not None:
            if length_unit == read_unit:
                conditions.append(_condition(
                    "variable", "pass",
                    f"检查 {check_id} 声明 length_unit={length_unit}，覆盖读取长度变量"))
            else:
                conditions.append(_condition(
                    "variable", "fail",
                    f"检查 {check_id} 的 length_unit={length_unit}，读取为 {read_unit}"))
        else:
            conditions.append(_condition(
                "variable", "unknown",
                f"检查 {check_id} 只声明 offset_unit={check_unit}；"
                "不能因为存在偏移比较就认定覆盖后续读取长度",
                "缺少长度比较变量与单位声明"))

    if check is None:
        conditions.append(_condition(
            "presence", "unknown", "检查记录缺失，无法核对变体编译范围", "缺少检查的 present_in"))
    elif "present_in" not in check:
        conditions.append(_condition(
            "presence", "unknown",
            f"检查 {check_id} 未声明 present_in，无法确认在 {variant} 变体编译产物中存在",
            "缺少检查的变体编译范围"))
    elif variant in (check.get("present_in") or []):
        conditions.append(_condition(
            "presence", "pass", f"检查 {check_id} 声明存在于 {variant} 变体"))
    else:
        conditions.append(_condition(
            "presence", "fail",
            f"检查 {check_id} 只出现在 {check.get('present_in')}，{variant} 变体没有该检查"))

    proof = read.get("proof")
    if proof == "complete":
        conditions.append(_condition(
            "proof", "pass", f"语句摘要 {read.get('id')} 声明 proof=complete"))
    elif proof == "incomplete":
        conditions.append(_condition(
            "proof", "fail", f"语句摘要 {read.get('id')} 自称 proof=incomplete，未证明覆盖该读取"))
    elif proof is None:
        conditions.append(_condition(
            "proof", "unknown", f"语句摘要 {read.get('id')} 未声明 proof，无法确认覆盖范围",
            "缺少语句摘要完整性声明"))
    else:
        conditions.append(_condition(
            "proof", "unknown", f"语句摘要 {read.get('id')} 的 proof 取值 {proof} 无法识别",
            "缺少可识别的语句摘要完整性声明"))

    if read.get("callers") or read.get("call_site") or read.get("guard"):
        conditions.append(_condition(
            "call_path", "pass", f"读取 {read.get('id')} 声明了调用者、调用点或守卫关系"))
    else:
        conditions.append(_condition(
            "call_path", "unknown",
            f"reads 记录 {read.get('id')} 没有 callers/call_site/guard 字段；"
            "资料未给出调用关系，无法确认读取只在检查之后可达",
            "缺少调用者、调用点或守卫关系"))

    if layout is None:
        conditions.append(_condition(
            "layout_resolution", "fail",
            f"无法从发布记录或 layout.kind 解析 {variant} 变体使用的布局"))
    elif layout_basis == "release.normal_layouts":
        conditions.append(_condition(
            "layout_resolution", "pass",
            f"发布记录 {layout_basis} 声明 {variant} 的正常布局为 {layout.get('id')}"))
    else:
        conditions.append(_condition(
            "layout_resolution", "unknown",
            f"仅按 layout.kind={variant} 推断为 {layout.get('id')}；"
            "发布记录未声明该变体的正常布局",
            "缺少变体到布局的显式映射"))

    if layout is None:
        conditions.append(_condition(
            "layout_unit", "unknown", "布局未解析，无法核对计量单位", "缺少布局记录"))
    else:
        layout_unit = _layout_unit(layout)
        if layout_unit is None:
            conditions.append(_condition(
                "layout_unit", "unknown",
                f"布局 {layout.get('id')} 未声明计量单位", "缺少布局计量单位"))
        elif read_unit == layout_unit and check_unit == layout_unit:
            conditions.append(_condition(
                "layout_unit", "pass",
                f"布局 {layout.get('id')}、读取长度与检查偏移均以 {layout_unit} 计量"))
        else:
            conditions.append(_condition(
                "layout_unit", "fail",
                f"布局 {layout.get('id')} 以 {layout_unit} 计量，"
                f"读取长度单位为 {read_unit}，检查偏移单位为 {check_unit}；"
                "单位不同，约束不覆盖该布局上的读取"))

    if layout is None:
        conditions.append(_condition(
            "outer_length", "unknown", "布局未解析，无法判断外层长度依赖",
            "缺少布局记录"))
    elif not layout.get("overall_buffer"):
        conditions.append(_condition(
            "outer_length", "not_applicable",
            f"布局 {layout.get('id')} 未声明 overall_buffer，不适用外层长度条件"))
    else:
        outer = layout.get("overall_buffer")
        layout_unit = _layout_unit(layout)
        reference = check.get("outer_length_ref") if check else None
        if reference != outer:
            conditions.append(_condition(
                "outer_length", "unknown",
                f"布局 {layout.get('id')} 依赖 overall_buffer={outer} 的外层长度，"
                f"但检查 {check_id} 未声明 outer_length_ref={outer}",
                "缺少外层长度引用"))
        elif read_unit != layout_unit:
            conditions.append(_condition(
                "outer_length", "fail",
                f"外层长度以 {layout_unit} 计，读取长度以 {read_unit} 计"))
        else:
            conditions.append(_condition(
                "outer_length", "pass",
                f"检查 {check_id} 以 overall_buffer={outer} 的外层长度推导子段上界"))

    limit = layout.get("public_max_bytes") if layout else None
    if layout is None:
        conditions.append(_condition(
            "fixed_buffer", "unknown", "布局未解析，无法核对固定缓冲区上限",
            "缺少布局记录"))
    elif limit is None:
        conditions.append(_condition(
            "fixed_buffer", "not_applicable",
            f"布局 {layout.get('id')} 未声明 public_max_bytes，不适用固定上限条件"))
    elif check is not None and check.get("max_bytes") == limit:
        conditions.append(_condition(
            "fixed_buffer", "pass",
            f"检查 {check_id} 引用固定上限 public_max_bytes={limit}"))
    else:
        conditions.append(_condition(
            "fixed_buffer", "unknown",
            f"布局 {layout.get('id')} 声明 public_max_bytes={limit}，"
            f"但检查 {check_id} 未声明所比较的最大字节数",
            "缺少固定缓冲区上限与检查的对应"))

    relevant = [
        release for release in releases
        if release.get("version") == version and release.get("variant") == variant
    ]
    if not relevant:
        conditions.append(_condition(
            "build", "unknown",
            f"没有 {version}/{variant} 的发布记录，无法确认实际构建",
            "缺少该版本与变体的发布记录"))
    else:
        active = [release for release in relevant if release.get("activated") is True]
        inactive = [release for release in relevant if release.get("activated") is False]
        if active:
            if any(_release_contains(release, check_id, node) for release in active):
                conditions.append(_condition(
                    "build", "pass",
                    f"已启用发布 {[r.get('id') for r in active]} 列出所含检查 {check_id}"))
            else:
                conditions.append(_condition(
                    "build", "unknown",
                    f"已启用发布 {[r.get('id') for r in active]} 未列出所含检查 {check_id}，"
                    "无法证明实际构建包含修复",
                    "缺少发布记录中的 includes_checks/fixes 字段"))
        elif len(inactive) == len(relevant):
            conditions.append(_condition(
                "build", "fail",
                f"发布记录 {[r.get('id') for r in inactive]} 声明 activated=false，"
                "修复未进入实际构建"))
        else:
            conditions.append(_condition(
                "build", "unknown",
                f"发布记录 {[r.get('id') for r in relevant]} 未声明 activated，"
                "无法确认实际构建启用状态",
                "缺少发布记录的激活状态"))

    if not relevant:
        conditions.append(_condition(
            "normal_read", "unknown",
            f"没有 {version}/{variant} 的发布记录，无法核对正常读取结果",
            "缺少该版本与变体的发布记录"))
    else:
        results = [(_normal_read_result(release, layout), release) for release in relevant]
        good = [release for result, release in results if result == "ok"]
        bad = [(result, release) for result, release in results if result not in (None, "ok")]
        if good:
            conditions.append(_condition(
                "normal_read", "pass",
                f"发布 {[r.get('id') for r in good]} 给出有效布局的正常读取结果"))
        elif bad:
            result, release = bad[0]
            conditions.append(_condition(
                "normal_read", "fail",
                f"发布 {release.get('id')} 的正常读取结果为 {result}，未证明有效布局可正常读取"))
        else:
            conditions.append(_condition(
                "normal_read", "unknown",
                f"发布 {[r.get('id') for r in relevant]} 未给出有效布局在 {variant} 变体的正常读取结果",
                "缺少正常读取结果记录"))

    statuses = {condition["status"] for condition in conditions}
    if "fail" in statuses:
        status = "unsupported"
    elif "unknown" in statuses:
        status = "unverified"
    else:
        status = "protected"

    return {
        "path_id": f"{node}@{version}/{variant}",
        "applicability": {
            "node": node,
            "version": version,
            "variant": variant,
            "layout": layout.get("id") if layout else None,
            "check": check_id,
            "read_target": target,
            "length_unit": read_unit,
            "filtered": layout_basis == "release.normal_layouts",
        },
        "variant_basis": variant_basis,
        "status": status,
        "conditions": conditions,
        "protected_constraints": [
            condition["id"] for condition in conditions if condition["status"] == "pass"],
        "unverified_constraints": [
            condition["id"] for condition in conditions if condition["status"] == "unknown"],
        "unprotected_constraints": [
            condition["id"] for condition in conditions if condition["status"] == "fail"],
    }


def _collect_missing(paths):
    missing = {}
    for path in paths:
        for condition in path["conditions"]:
            if condition["status"] != "unknown" or "missing_basis" not in condition:
                continue
            key = (condition["id"], condition["missing_basis"])
            entry = missing.setdefault(key, {
                "id": f"ME-{condition['code']}",
                "condition": condition["id"],
                "code": condition["code"],
                "basis": condition["missing_basis"],
                "boundary": condition["boundary"],
                "affects": [],
            })
            if path["path_id"] not in entry["affects"]:
                entry["affects"].append(path["path_id"])
    return list(missing.values())


def _collect_findings(paths):
    findings = []
    for path in paths:
        for condition in path["conditions"]:
            if condition["status"] != "fail":
                continue
            findings.append({
                "code": condition["code"],
                "path_id": path["path_id"],
                "condition": condition["id"],
                "applicability": path["applicability"],
                "boundary": condition["boundary"],
                "detail": condition["detail"],
            })
    return findings


def _handoff(paths):
    items = []
    for path in paths:
        if path["status"] == "protected":
            continue
        applicability = path["applicability"]
        remaining = [
            {
                "condition": condition["id"],
                "code": condition["code"],
                "status": condition["status"],
                "boundary": condition["boundary"],
                "detail": condition["detail"],
            }
            for condition in path["conditions"]
            if condition["status"] in ("fail", "unknown")
        ]
        items.append({
            "path_id": path["path_id"],
            "status": path["status"],
            "observable": (
                f"{applicability['variant']} 变体 / 版本 {applicability['version']} / "
                f"节点 {applicability['node']} / 读取 {applicability['read_target']} / "
                f"检查 {applicability['check']} / 布局 {applicability['layout']}"),
            "remaining": remaining,
            "next_action": "补齐上述依据后重新审计该路径；不存在触发字节或报文样本。",
        })
    return items


def apply_corrections(sources, corrections):
    """应用评审提交的更正语句摘要：按来源、按 id 整体替换或追加。"""
    if not isinstance(corrections, dict):
        raise ValueError("更正材料需要对象")
    updated = {name: [dict(row) for row in rows] for name, rows in sources.items()}
    applied = []
    for name, rows in corrections.items():
        if name not in updated:
            raise ValueError(f"更正材料包含未知来源 {name}")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"更正材料 {name} 需要对象数组")
        batch = [row.get("id") for row in rows]
        if len(batch) != len(set(batch)):
            raise ValueError(f"更正材料 {name} 的记录标识重复")
        index = {row["id"]: position for position, row in enumerate(updated[name])}
        for row in rows:
            identifier = row.get("id")
            if not isinstance(identifier, str) or not identifier:
                raise ValueError(f"更正材料 {name} 缺少记录标识")
            if identifier in index:
                updated[name][index[identifier]] = dict(row)
                action = "replace"
            else:
                index[identifier] = len(updated[name])
                updated[name].append(dict(row))
                action = "add"
            applied.append({"source": name, "id": identifier, "action": action})
    for name, rows in updated.items():
        identifiers = [row["id"] for row in rows]
        duplicates = {key for key in identifiers if identifiers.count(key) > 1}
        if duplicates:
            raise ValueError(f"更正后的 {name} 记录标识重复: {sorted(duplicates)}")
    return updated, applied


def audit(sources, corrections=None):
    applied = []
    if corrections is not None:
        sources, applied = apply_corrections(sources, corrections)

    for name in SOURCE_NAMES:
        if name not in sources:
            raise ValueError(f"缺少来源 {name}")

    layouts = list(sources["layouts"])
    reads = list(sources["reads"])
    releases = list(sources["releases"])
    checks = {}
    for row in reads:
        if "bounds" not in row:
            continue
        for key in (row.get("node"), row.get("id")):
            if key:
                checks[key] = row
    read_statements = [row for row in reads if "reads" in row]

    paths = []
    for read in read_statements:
        variants, variant_basis = _variants_for(read, releases)
        check = checks.get(read.get("uses_check"))
        for variant in (variants or [None]):
            layout, layout_basis, _ = resolve_layout(variant, layouts, releases)
            paths.append(_evaluate_path(
                read, check, variant, variant_basis, layout, layout_basis, releases))

    findings = _collect_findings(paths)
    missing = _collect_missing(paths)
    missing.append({
        "id": "ME-PUBLIC-INTERFACE",
        "condition": "public_interface",
        "code": "F-PUBLIC-INTERFACE",
        "basis": "layouts 与 releases 均未声明普通维护接口读取的布局",
        "boundary": "普通维护接口继续读取已确认安全的布局",
        "affects": [path["path_id"] for path in paths],
    })

    summary = {
        "paths": len(paths),
        "protected": sum(path["status"] == "protected" for path in paths),
        "unsupported": sum(path["status"] == "unsupported" for path in paths),
        "unverified": sum(path["status"] == "unverified" for path in paths),
        "findings": len(findings),
        "missing_evidence": len(missing),
    }
    summary["ok"] = summary["protected"] == len(paths) and not findings and not missing

    return {
        "tool": "buffer-boundary-static-audit",
        "mode": "offline-static",
        "disclaimer": "仅使用本地合成记录；未连接设备，未生成或发送任何报文，未输出触发字节。",
        "inputs": {name: len(sources[name]) for name in SOURCE_NAMES},
        "review": {"corrections_applied": applied},
        "summary": summary,
        "paths": paths,
        "findings": findings,
        "missing_evidence": missing,
        "handoff": _handoff(paths),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, default=Path(__file__).with_name("records"))
    parser.add_argument("--corrections", type=Path,
                        help="评审提交的更正语句摘要（按来源、按 id 替换或追加）")
    parser.add_argument("--pretty", action="store_true", help="缩进输出")
    args = parser.parse_args()
    try:
        sources = load_sources(args.records)
        corrections = None
        if args.corrections is not None:
            corrections = json.loads(args.corrections.read_text(encoding="utf-8"))
        report = audit(sources, corrections)
    except (ValueError, OSError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(report, ensure_ascii=False, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
