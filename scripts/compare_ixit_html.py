#!/usr/bin/env python3
"""
生成 ixit.json 新旧对比 HTML 页面。

用法:
  python compare_ixit_html.py <old.json> <new.json> [output.html]

输出自包含 HTML（数据内嵌），可直接在浏览器中打开复核。
"""

import json
import os
import sys
from html import escape as html_escape


def h(text):
    """HTML-escape shorthand."""
    if text is None:
        return ""
    return html_escape(str(text), quote=True)


def diff_class(old_val, new_val):
    """Return CSS class based on whether values differ."""
    if old_val == new_val:
        return ""
    if not old_val and new_val:
        return "diff-added"
    if old_val and not new_val:
        return "diff-removed"
    return "diff-changed"


def build_html(old_data, new_data):
    """Build the full HTML string."""

    # --- Compute stats ---
    old_ics_count = len(old_data.get("ics", []))
    new_ics_count = len(new_data.get("ics", []))
    ics_match = sum(1 for a, b in zip(old_data.get("ics", []), new_data.get("ics", [])) if a == b)
    ics_diff = min(old_ics_count, new_ics_count) - ics_match

    old_dut = old_data.get("meta", {}).get("dut_identification", {})
    new_dut = new_data.get("meta", {}).get("dut_identification", {})

    old_tables = old_data.get("ixit_tables", {})
    new_tables = new_data.get("ixit_tables", {})
    all_table_names = sorted(set(list(old_tables.keys()) + list(new_tables.keys())))
    table_match = sum(1 for t in all_table_names if old_tables.get(t) == new_tables.get(t))
    table_diff = len(all_table_names) - table_match

    # --- Build ICS rows HTML ---
    ics_rows_html = ""
    max_ics = max(old_ics_count, new_ics_count)
    for i in range(max_ics):
        o = old_data["ics"][i] if i < old_ics_count else {}
        n = new_data["ics"][i] if i < new_ics_count else {}
        row_class = "" if o == n else "row-diff"
        # Extract provision number from reference
        ref = n.get("reference", o.get("reference", ""))
        prov_num = ""
        if ref.startswith("Provision "):
            parts = ref.split(" ", 2)
            prov_num = parts[1] if len(parts) > 1 else ""

        def td_field(key):
            ov = o.get(key, "")
            nv = n.get(key, "")
            cls = diff_class(ov, nv)
            if ov == nv:
                return f'<td class="{cls}">{h(nv)}</td>'
            return f'<td class="{cls}"><span class="old">{h(ov)}</span><span class="new">{h(nv)}</span></td>'

        ics_rows_html += f"""<tr class="{row_class}">
  <td>{i+1}</td>
  <td>{h(prov_num)}</td>
  {td_field("applicability")}
  <td class="ref-cell">{h(ref)}</td>
  {td_field("status")}
  {td_field("en18031")}
</tr>\n"""

    # --- Build DUT Identification HTML ---
    dut_rows_html = ""
    all_sections = sorted(set(list(old_dut.keys()) + list(new_dut.keys())))
    for sec in all_sections:
        o_sec = old_dut.get(sec, {})
        n_sec = new_dut.get(sec, {})
        sec_class = "" if o_sec == n_sec else "row-diff"
        dut_rows_html += f'<tr class="section-header {sec_class}"><td colspan="3">{h(sec)}</td></tr>\n'

        if isinstance(n_sec, dict) or isinstance(o_sec, dict):
            all_fields = sorted(set(list(
                (o_sec if isinstance(o_sec, dict) else {}).keys()) + list(
                (n_sec if isinstance(n_sec, dict) else {}).keys())))
            for field in all_fields:
                ov = (o_sec if isinstance(o_sec, dict) else {}).get(field, "<missing>")
                nv = (n_sec if isinstance(n_sec, dict) else {}).get(field, "<missing>")
                cls = diff_class(ov, nv)
                if ov == nv:
                    dut_rows_html += f'<tr><td></td><td>{h(field)}</td><td>{h(nv)}</td></tr>\n'
                else:
                    dut_rows_html += f'<tr class="row-diff"><td></td><td>{h(field)}</td>'
                    dut_rows_html += f'<td class="{cls}"><span class="old">{h(ov)}</span><span class="new">{h(nv)}</span></td></tr>\n'

    # --- Build IXIT Tables HTML ---
    tables_html = ""
    for tname in all_table_names:
        o_table = old_tables.get(tname, {"meta": {"row_count": 0, "columns": []}, "rows": []})
        n_table = new_tables.get(tname, {"meta": {"row_count": 0, "columns": []}, "rows": []})
        match = o_table == n_table
        badge = '<span class="badge badge-ok">MATCH</span>' if match else '<span class="badge badge-diff">DIFF</span>'

        o_rows = o_table.get("rows", [])
        n_rows = n_table.get("rows", [])
        cols = n_table.get("meta", {}).get("columns", o_table.get("meta", {}).get("columns", []))
        layout = n_table.get("meta", {}).get("layout", o_table.get("meta", {}).get("layout", "?"))

        tables_html += f"""<details {'open' if not match else ''}>
<summary>{h(tname)} {badge} <small>({len(o_rows)} vs {len(n_rows)} rows, {layout})</small></summary>
<table class="detail-table">
<thead><tr><th>#</th>{"".join(f'<th>{h(c)}</th>' for c in cols)}</tr></thead>
<tbody>
"""
        max_rows = max(len(o_rows), len(n_rows))
        for ri in range(max_rows):
            o_row = o_rows[ri] if ri < len(o_rows) else {}
            n_row = n_rows[ri] if ri < len(n_rows) else {}
            row_match = o_row == n_row
            row_cls = "" if row_match else "row-diff"
            tables_html += f'<tr class="{row_cls}"><td>{ri+1}</td>'
            for col in cols:
                ov = o_row.get(col, "")
                nv = n_row.get(col, "")
                cls = diff_class(ov, nv)
                if ov == nv:
                    tables_html += f'<td class="{cls}">{h(str(nv))}</td>'
                else:
                    tables_html += f'<td class="{cls}">'
                    if ov:
                        tables_html += f'<span class="old">{h(str(ov))}</span>'
                    tables_html += f'<span class="new">{h(str(nv))}</span></td>'
            tables_html += '</tr>\n'

        tables_html += '</tbody></table></details>\n'

    # --- Assemble full HTML ---
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IXIT JSON 比对 — 人工复核</title>
<style>
:root {{
  --bg: #1a1a2e; --surface: #16213e; --text: #e0e0e0;
  --accent: #0f3460; --highlight: #e94560;
  --added-bg: #1b3a1b; --added-border: #4caf50;
  --removed-bg: #3a1b1b; --removed-border: #f44336;
  --changed-bg: #3a3a1b; --changed-border: #ff9800;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 16px; }}
h1 {{ text-align: center; margin: 16px 0; font-size: 1.5em; }}
h2 {{ margin: 16px 0 8px; padding: 8px 12px; background: var(--accent); border-radius: 6px; }}
.stats {{ display: flex; gap: 16px; justify-content: center; flex-wrap: wrap; margin: 16px 0; }}
.stat-card {{ background: var(--surface); border-radius: 8px; padding: 16px 24px; text-align: center; min-width: 140px; }}
.stat-card .num {{ font-size: 2em; font-weight: bold; }}
.stat-card .label {{ font-size: 0.85em; opacity: 0.7; margin-top: 4px; }}
.stat-ok .num {{ color: #4caf50; }}
.stat-diff .num {{ color: #ff9800; }}
.tabs {{ display: flex; gap: 4px; margin: 16px 0 8px; border-bottom: 2px solid var(--accent); }}
.tab {{ padding: 8px 20px; cursor: pointer; border-radius: 6px 6px 0 0; background: var(--surface); }}
.tab.active {{ background: var(--accent); font-weight: bold; }}
.tab-content {{ display: none; }}
.tab-content.active {{ display: block; }}
table {{ width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 0.85em; }}
th, td {{ padding: 6px 10px; border: 1px solid #333; text-align: left; vertical-align: top; word-break: break-word; }}
th {{ background: var(--accent); position: sticky; top: 0; }}
tr:nth-child(even) {{ background: rgba(255,255,255,0.03); }}
.row-diff {{ background: rgba(233,69,96,0.1) !important; }}
.diff-added {{ background: var(--added-bg); border-left: 3px solid var(--added-border); }}
.diff-removed {{ background: var(--removed-bg); border-left: 3px solid var(--removed-border); }}
.diff-changed {{ background: var(--changed-bg); border-left: 3px solid var(--changed-border); }}
span.old {{ display: block; text-decoration: line-through; opacity: 0.5; font-size: 0.9em; }}
span.new {{ display: block; font-weight: bold; }}
.section-header td {{ background: var(--accent); font-weight: bold; font-size: 1em; }}
.ref-cell {{ max-width: 500px; font-size: 0.8em; white-space: pre-wrap; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.75em; font-weight: bold; }}
.badge-ok {{ background: #1b3a1b; color: #4caf50; }}
.badge-diff {{ background: #3a1b1b; color: #ff9800; }}
details {{ margin: 4px 0; }}
summary {{ cursor: pointer; padding: 8px 12px; background: var(--surface); border-radius: 4px; font-weight: bold; }}
summary:hover {{ background: var(--accent); }}
.detail-table {{ margin: 4px 0 16px; }}
.filter-bar {{ margin: 8px 0; display: flex; gap: 8px; align-items: center; }}
.filter-bar label {{ cursor: pointer; }}
.filter-bar input[type="checkbox"] {{ margin-right: 4px; }}
</style>
</head>
<body>

<h1>📋 IXIT JSON 比对 — 人工复核</h1>

<div class="stats">
  <div class="stat-card {'stat-ok' if ics_diff == 0 else 'stat-diff'}">
    <div class="num">{ics_match}/{max_ics}</div>
    <div class="label">ICS 一致</div>
  </div>
  <div class="stat-card {'stat-ok' if table_diff == 0 else 'stat-diff'}">
    <div class="num">{table_match}/{len(all_table_names)}</div>
    <div class="label">IXIT 表一致</div>
  </div>
  <div class="stat-card">
    <div class="num">{new_ics_count}</div>
    <div class="label">ICS 条目</div>
  </div>
  <div class="stat-card">
    <div class="num">{len(all_table_names)}</div>
    <div class="label">IXIT Sheets</div>
  </div>
</div>

<div class="tabs">
  <div class="tab active" onclick="switchTab('ics')">ICS ({ics_diff} diff)</div>
  <div class="tab" onclick="switchTab('dut')">DUT ID</div>
  <div class="tab" onclick="switchTab('tables')">IXIT Tables ({table_diff} diff)</div>
</div>

<div id="tab-ics" class="tab-content active">
  <h2>ICS — Implementation Conformance Statement</h2>
  <div class="filter-bar">
    <label><input type="checkbox" id="showAllIcs" checked onchange="toggleIcsFilter()"> 显示全部</label>
    <label><input type="checkbox" id="showDiffOnly" onchange="toggleIcsFilter()"> 仅显示差异</label>
  </div>
  <table>
    <thead><tr><th>#</th><th>Provision</th><th>Applicability</th><th>Reference</th><th>Status</th><th>EN18031</th></tr></thead>
    <tbody>{ics_rows_html}</tbody>
  </table>
</div>

<div id="tab-dut" class="tab-content">
  <h2>DUT Identification</h2>
  <table>
    <thead><tr><th></th><th>Field</th><th>Value</th></tr></thead>
    <tbody>{dut_rows_html}</tbody>
  </table>
</div>

<div id="tab-tables" class="tab-content">
  <h2>IXIT Tables</h2>
  {tables_html}
</div>

<script>
function switchTab(name) {{
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
}}
function toggleIcsFilter() {{
  const diffOnly = document.getElementById('showDiffOnly').checked;
  document.querySelectorAll('#tab-ics tbody tr').forEach(tr => {{
    if (diffOnly && !tr.classList.contains('row-diff')) {{
      tr.style.display = 'none';
    }} else {{
      tr.style.display = '';
    }}
  }});
}}
</script>

</body>
</html>"""
    return html


def main():
    if len(sys.argv) < 3:
        print("用法: python compare_ixit_html.py <old.json> <new.json> [output.html]",
              file=sys.stderr)
        return 2

    old_path = sys.argv[1]
    new_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else os.path.join(
        os.path.dirname(new_path), "ixit_compare.html"
    )

    with open(old_path, "r", encoding="utf-8") as f:
        old_data = json.load(f)
    with open(new_path, "r", encoding="utf-8") as f:
        new_data = json.load(f)

    html = build_html(old_data, new_data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"比对页面已生成: {output_path} ({os.path.getsize(output_path) / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
