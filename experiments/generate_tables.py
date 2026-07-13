import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.evaluation.eval_runner import (
    run_mcptox_experiment,
    run_multi_model_experiment,
    run_t3_experiment,
    run_ablation_experiment,
    run_per_category_experiment,
    run_per_layer_experiment,
    run_latency_profile_experiment,
)
from src.evaluation.multi_run import multi_run


def generate_paper_tables():
    results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "results")
    os.makedirs(results_dir, exist_ok=True)

    mcptox = run_mcptox_experiment(mock_mode=True)
    multi = run_multi_model_experiment(mock_mode=True)
    t3 = run_t3_experiment(mock_mode=True)
    ablation = run_ablation_experiment(mock_mode=True)
    per_cat = run_per_category_experiment(mock_mode=True)
    per_layer = run_per_layer_experiment(mock_mode=True)
    latency = run_latency_profile_experiment(mock_mode=True)

    mcptox_ci = multi_run(lambda: run_mcptox_experiment(mock_mode=True), num_runs=3)

    all_data = {
        "mcptox_main": mcptox,
        "mcptox_ci": mcptox_ci,
        "multi_model": multi,
        "t3": t3,
        "ablation": ablation,
        "per_category": per_cat,
        "per_layer": per_layer,
        "latency_profile": latency,
    }
    with open(os.path.join(results_dir, "experiment_results.json"), "w") as f:
        json.dump(all_data, f, indent=2)

    latex_dir = os.path.join(results_dir, "latex_tables")
    os.makedirs(latex_dir, exist_ok=True)

    _write_main_table(mcptox, mcptox_ci, os.path.join(latex_dir, "tab_main.tex"))
    _write_multi_model_table(multi, os.path.join(latex_dir, "tab_multi_model.tex"))
    _write_t3_table(t3, os.path.join(latex_dir, "tab_t3.tex"))
    _write_ablation_table(ablation, os.path.join(latex_dir, "tab_ablation.tex"))
    _write_per_category_table(per_cat, os.path.join(latex_dir, "tab_per_category.tex"))
    _write_per_layer_table(per_layer, os.path.join(latex_dir, "tab_per_layer.tex"))
    _write_latency_table(latency, os.path.join(latex_dir, "tab_latency.tex"))

    print(f"LaTeX tables written to {latex_dir}/")


def _write_main_table(data, ci_data, path):
    rows = []
    for dname in ["No Defense", "AttestMCP", "Guardrail", "PTG-Only", "RTV-Only", "ReasoningGuard"]:
        m = data[dname]
        lat = "---" if m["Latency_ms"] == 0 else f"{m['Latency_ms']:.1f}"
        bold = "\\textbf" if dname == "ReasoningGuard" else ""
        ci = ci_data.get(dname, {})
        asr_ci = ci.get("ASR_ci", 0)
        tcr_ci = ci.get("TCR_ci", 0)
        asr_str = f"{m['ASR']:.1f}" + (f" ± {asr_ci:.1f}" if asr_ci else "")
        tcr_str = f"{m['TCR']:.1f}" + (f" ± {tcr_ci:.1f}" if tcr_ci else "")
        rows.append(
            f"{bold}{{{dname}}} & {bold}{{{asr_str}}} & {bold}{{{tcr_str}}} & {lat} \\\\"
        )
    tex = (
        "\\begin{table}[t]\n\\centering\\small\n"
        "\\begin{tabular}{lccc}\n\\toprule\n"
        "\\textbf{Defense} & \\textbf{ASR (\\%)} & \\textbf{TCR (\\%)} & \\textbf{Latency (ms)} \\\\\n"
        "\\midrule\n"
        + "\n".join(rows)
        + "\n\\bottomrule\n\\end{tabular}\n"
        "\\caption{Main results on MCPTox (GPT-4o, $n{=}3$ runs, 95\\% CI). ASR=Attack Success Rate, TCR=Task Completion Rate.}\n"
        "\\label{tab:main}\n\\end{table}\n"
    )
    with open(path, "w") as f:
        f.write(tex)


def _write_multi_model_table(data, path):
    rows = []
    for model in ["GPT-4o", "Claude-3.5-Sonnet", "Gemini-1.5-Pro", "Llama-3.1-70B"]:
        for dname in ["No Defense", "AttestMCP", "ReasoningGuard"]:
            m = data[model][dname]
            bold = "\\textbf" if dname == "ReasoningGuard" else ""
            rows.append(
                f"{model} & {dname} & {bold}{{{m['ASR']:.1f}}} & {bold}{{{m['TCR']:.1f}}} & {m['Latency_ms']:.1f} \\\\"
            )
    tex = (
        "\\begin{table}[t]\n\\centering\\small\n"
        "\\begin{tabular}{llccc}\n\\toprule\n"
        "\\textbf{Model} & \\textbf{Defense} & \\textbf{ASR (\\%)} & \\textbf{TCR (\\%)} & \\textbf{Lat. (ms)} \\\\\n"
        "\\midrule\n"
        + "\n".join(rows)
        + "\n\\bottomrule\n\\end{tabular}\n"
        "\\caption{Multi-model results on MCPTox.}\n"
        "\\label{tab:multi_model}\n\\end{table}\n"
    )
    with open(path, "w") as f:
        f.write(tex)


def _write_t3_table(data, path):
    rows = []
    for dname in ["No Defense", "AttestMCP", "PTG-Only", "RTV-Only", "ReasoningGuard"]:
        m = data[dname]
        bold = "\\textbf" if dname == "ReasoningGuard" else ""
        rows.append(
            f"{bold}{{{dname}}} & {bold}{{{m['T3_ASR']:.1f}}} & {bold}{{{m['T1_ASR']:.1f}}} \\\\"
        )
    tex = (
        "\\begin{table}[t]\n\\centering\\small\n"
        "\\begin{tabular}{lcc}\n\\toprule\n"
        "\\textbf{Defense} & \\textbf{T3 ASR (\\%)} & \\textbf{T1 ASR (\\%)} \\\\\n"
        "\\midrule\n"
        + "\n".join(rows)
        + "\n\\bottomrule\n\\end{tabular}\n"
        "\\caption{Cross-session (T3) vs.\\ instantaneous (T1) results on MCPTox+.}\n"
        "\\label{tab:t3}\n\\end{table}\n"
    )
    with open(path, "w") as f:
        f.write(tex)


def _write_ablation_table(data, path):
    rows = []
    for variant, m in data.items():
        rows.append(f"{variant} & {m['ASR']:.1f} & {m['T3_ASR']:.1f} & {m['TCR']:.1f} \\\\")
    tex = (
        "\\begin{table}[t]\n\\centering\\small\n"
        "\\begin{tabular}{lccc}\n\\toprule\n"
        "\\textbf{Variant} & \\textbf{ASR (\\%)} & \\textbf{T3 ASR (\\%)} & \\textbf{TCR (\\%)} \\\\\n"
        "\\midrule\n"
        + "\n".join(rows)
        + "\n\\bottomrule\n\\end{tabular}\n"
        "\\caption{Ablation study on MCPTox and MCPTox+ (GPT-4o). Each row removes one component.}\n"
        "\\label{tab:ablation}\n\\end{table}\n"
    )
    with open(path, "w") as f:
        f.write(tex)


def _write_per_category_table(data, path):
    defenses = ["No Defense", "AttestMCP", "PTG-Only", "RTV-Only", "ReasoningGuard"]
    header = "\\textbf{Category} & " + " & ".join(f"\\textbf{{{d}}}" for d in defenses) + " \\\\"
    rows = []
    for cat, defs in data.items():
        vals = " & ".join(f"{defs[d]:.1f}" for d in defenses)
        rows.append(f"{cat} & {vals} \\\\")
    tex = (
        "\\begin{table}[t]\n\\centering\\small\n"
        "\\begin{tabular}{l" + "c" * len(defenses) + "}\n\\toprule\n"
        + header + "\n\\midrule\n"
        + "\n".join(rows)
        + "\n\\bottomrule\n\\end{tabular}\n"
        "\\caption{ASR (\\%) per attack category on MCPTox+ (GPT-4o).}\n"
        "\\label{tab:per_category}\n\\end{table}\n"
    )
    with open(path, "w") as f:
        f.write(tex)


def _write_per_layer_table(data, path):
    rows = []
    for dname in ["No Defense", "AttestMCP", "PTG-Only", "RTV-Only", "ReasoningGuard"]:
        m = data[dname]
        bold = "\\textbf" if dname == "ReasoningGuard" else ""
        rows.append(
            f"{bold}{{{dname}}} & {bold}{{{m['L4_ASR']:.1f}}} & {bold}{{{m['L2_ASR']:.1f}}} \\\\"
        )
    tex = (
        "\\begin{table}[t]\n\\centering\\small\n"
        "\\begin{tabular}{lcc}\n\\toprule\n"
        "\\textbf{Defense} & \\textbf{L4 ASR (\\%)} & \\textbf{L2 ASR (\\%)} \\\\\n"
        "\\midrule\n"
        + "\n".join(rows)
        + "\n\\bottomrule\n\\end{tabular}\n"
        "\\caption{Per-layer ASR on MCPTox+. L4=protocol-layer attacks, L2=reasoning-layer attacks.}\n"
        "\\label{tab:per_layer}\n\\end{table}\n"
    )
    with open(path, "w") as f:
        f.write(tex)


def _write_latency_table(data, path):
    rows = []
    for comp, stats in data.items():
        label = comp.replace("_", "\\_")
        rows.append(f"{label} & {stats['mean_ms']:.1f} & {stats['median_ms']:.1f} \\\\")
    tex = (
        "\\begin{table}[t]\n\\centering\\small\n"
        "\\begin{tabular}{lcc}\n\\toprule\n"
        "\\textbf{Component} & \\textbf{Mean (ms)} & \\textbf{Median (ms)} \\\\\n"
        "\\midrule\n"
        + "\n".join(rows)
        + "\n\\bottomrule\n\\end{tabular}\n"
        "\\caption{Per-component latency breakdown of ReasoningGuard (GPT-4o, 200 scenarios).}\n"
        "\\label{tab:latency}\n\\end{table}\n"
    )
    with open(path, "w") as f:
        f.write(tex)


if __name__ == "__main__":
    generate_paper_tables()