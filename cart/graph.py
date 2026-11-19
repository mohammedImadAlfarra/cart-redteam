"""Attack-path graph: Target -> Endpoint -> Vulnerability -> Impact, plus chains."""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

SEV_COLOR = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb"}


def build_graph(result: dict) -> nx.DiGraph:
    g = nx.DiGraph()
    root = result.get("title", result["target"])
    g.add_node(root, kind="target")
    for f in result["findings"]:
        ep = f"{f['method']} {f['path']}"
        vuln = f"{f['id']}: {f['vuln_type']}"
        g.add_node(ep, kind="endpoint")
        g.add_node(vuln, kind="vuln", severity=f["severity"], status=f["status"])
        g.add_edge(root, ep)
        g.add_edge(ep, vuln)
        dep = f.get("remediation", {}).get("depends_on")
        if dep:
            other = next((x for x in result["findings"] if x["id"] == dep), None)
            if other:
                g.add_edge(f"{other['id']}: {other['vuln_type']}", vuln, chain=True)
    return g


def draw(result: dict, out_path: Path) -> Path:
    g = build_graph(result)
    if g.number_of_nodes() <= 1:
        g.add_node("no findings", kind="endpoint")
        g.add_edge(result.get("title", "target"), "no findings")
    pos = nx.spring_layout(g, seed=7, k=1.1)
    plt.figure(figsize=(11, 7))
    for kind, shape, size in [("target", "s", 2600), ("endpoint", "o", 1500), ("vuln", "o", 2100)]:
        nodes = [n for n, d in g.nodes(data=True) if d.get("kind") == kind]
        if kind == "vuln":
            colors = [SEV_COLOR.get(g.nodes[n].get("severity"), "#64748b") for n in nodes]
        else:
            colors = "#0f172a" if kind == "target" else "#94a3b8"
        nx.draw_networkx_nodes(g, pos, nodelist=nodes, node_color=colors, node_shape=shape,
                               node_size=size, edgecolors="white", linewidths=1.5)
    chain = [(u, v) for u, v, d in g.edges(data=True) if d.get("chain")]
    normal = [(u, v) for u, v, d in g.edges(data=True) if not d.get("chain")]
    nx.draw_networkx_edges(g, pos, edgelist=normal, edge_color="#cbd5e1", arrows=True, arrowsize=14)
    nx.draw_networkx_edges(g, pos, edgelist=chain, edge_color="#b91c1c", style="dashed",
                           arrows=True, arrowsize=18, width=2)
    nx.draw_networkx_labels(g, pos, font_size=7.5, font_color="#0f172a")
    plt.title(f"Attack-path graph - {result.get('title', result['target'])}", fontsize=12)
    plt.axis("off")
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=130, bbox_inches="tight")
    plt.close()
    return out_path
