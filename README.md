# 设备维护记录读取器的缓冲区边界审计

节点模型仅包含声明的区间、单位及检查引用，无固件、输入字节或运行器。 资料均为本地合成记录。

以 Python 3.11.2 运行，无第三方依赖。`records/` 中的 `layouts`、`reads`、`releases` 对应独立来源。每份材料是 JSON 对象数组，`id` 在同一来源内唯一。报告和观察的时间以各原始记录给出的字段为准。

```sh
python3 -m unittest -v
python3 records_view.py
python3 audit.py --pretty
```

资料入口列出来源、记录标识及条数。通过 `--source` 指定来源，`--offset` 和 `--limit` 限定读取的位置与数量。`--records` 可指定同样结构的其他资料目录。

## 静态边界审计

`audit.py` 只做离线静态核对：不连接设备，不生成或编码测试报文，报告只给出合成节点编号、适用条件与应验证的安全边界，不输出任何触发字节。

每个读取语句按“版本 + 变体”展开为一条可观察路径（`节点@版本/变体`），并逐项给出下列条件的状态（`pass` / `fail` / `unknown` / `not_applicable`）：

| 条件 | 含义 |
| --- | --- |
| `check_ref` / `check_version` | 被引用的检查存在，且与读取语句同版本 |
| `scope` | 子段读取需要同范围检查，整段（whole-frame）可读不替代子段界限 |
| `unit` / `variable` | 存在长度比较不等于覆盖后续读取；比较变量须含长度，单位须与读取一致 |
| `presence` | 检查出现在读取路径对应变体的编译产物中 |
| `proof` | 语句摘要完整覆盖该读取，`incomplete` 不视为覆盖 |
| `call_path` | 有调用者、调用点或守卫关系，能证明读取在检查之后可达 |
| `layout_resolution` / `layout_unit` / `outer_length` / `fixed_buffer` | 变体到布局有显式映射；偏移、长度与布局计量单位一致；依赖外层长度的布局须由该外层长度推导子段上界；固定上限须被检查引用 |
| `build` / `normal_read` | 实际构建包含该检查；有效布局在该变体给出正常读取结果 |

路径状态取各项中最差者：有 `fail` 为 `unsupported`，否则有 `unknown` 为 `unverified`，全部通过才为 `protected`。`missing_evidence` 汇总缺失的具体依据（如调用关系、语句摘要完整性、布局映射、构建激活状态），`findings` 列出可判定的缺陷，`handoff` 按可观察路径把未 `protected` 的剩余问题交给下一位维护人。

### 评审更正

评审可提交更正后的语句摘要，按来源、按 `id` 整体替换已有记录或追加新记录：

```sh
python3 audit.py --corrections corrections.json --pretty
```

顶层键为 `layouts` / `reads` / `releases`，值为对象数组。更正只作用于内存副本，不修改 `records/` 原始资料；报告 `review.corrections_applied` 记录每条替换/追加。补齐依据后，相应路径会转为 `protected`，仍未覆盖的路径继续出现在 `handoff` 中。

普通维护人员使用的接口布局目前没有在 `layouts` 或 `releases` 中声明，报告以 `ME-PUBLIC-INTERFACE` 指出这一缺口，不推测其安全性。

