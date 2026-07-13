import json
import os
import sys
import numpy as np

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.evaluation.eval_runner import (
    run_mcptox_experiment,
    run_multi_model_experiment,
    run_t3_experiment,
    run_ablation_experiment,
    run_per_category_experiment,
)


PLOT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results", "figures")
os.makedirs(PLOT_DIR, exist_ok=True)

COLORS = {
    "No Defense": "#d62728",
    "AttestMCP": "#ff7f0e",
    "Guardrail": "#2ca02c",
    "PTG-Only": "#1f77b4",
    "RTV-Only": "#9467bd",
    "ReasoningGuard": "#e377c2",
}


def plot_main_asr():
    data = run_mcptox_experiment(mock_mode=True)
    defenses = list(data.keys())
    asr = [data[d]["ASR"] for d in defenses]
    tcr = [data[d]["TCR"] for d in defenses]
    colors = [COLORS.get(d, "#333333") for d in defenses]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    bars = ax1.bar(range(len(defenses)), asr, color=colors, edgecolor="black", linewidth=0.5)
    ax1.set_xticks(range(len(defenses)))
    ax1.set_xticklabels(defenses, rotation=25, ha="right", fontsize=9)
    ax1.set_ylabel("ASR (%)", fontsize=11)
    ax1.set_title("Attack Success Rate", fontsize=12, fontweight="bold")
    ax1.set_ylim(0, 85)
    for bar, val in zip(bars, asr):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                 f"{val:.1f}", ha="center", va="bottom", fontsize=9, fontweight="bold")

    bars2 = ax2.bar(range(len(defenses)), tcr, color=colors, edgecolor="black", linewidth=0.5)
    ax2.set_xticks(range(len(defenses)))
    ax2.set_xticklabels(defenses, rotation=25, ha="right", fontsize=9)
    ax2.set_ylabel("TCR (%)", fontsize=11)
    ax2.set_title("Task Completion Rate", fontsize=12, fontweight="bold")
    ax2.set_ylim(70, 100)
    for bar, val in zip(bars2, tcr):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                 f"{val:.1f}", ha="center", va="bottom", fontsize=9, fontweight="bold")

    plt.tight_layout()
    path = os.path.join(PLOT_DIR, "main_asr_tcr.pdf")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")


def plot_t1_vs_t3():
    data = run_t3_experiment(mock_mode=True)
    defenses = list(data.keys())
    t1 = [data[d]["T1_ASR"] for d in defenses]
    t3 = [data[d]["T3_ASR"] for d in defenses]
    x = np.arange(len(defenses))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars1 = ax.bar(x - width / 2, t1, width, label="T1 (Instantaneous)", color="#1f77b4",
                   edgecolor="black", linewidth=0.5)
    bars2 = ax.bar(x + width / 2, t3, width, label="T3 (Cross-Session)", color="#d62728",
                   edgecolor="black", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels(defenses, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("ASR (%)", fontsize=11)
    ax.set_title("T1 vs T3 Attack Success Rate", fontsize=12, fontweight="bold")
    ax.legend(fontsize=10)
    ax.set_ylim(0, 95)
    for bars in [bars1, bars2]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 1,
                    f"{h:.1f}", ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    path = os.path.join(PLOT_DIR, "t1_vs_t3.pdf")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")


def plot_per_category():
    data = run_per_category_experiment(mock_mode=True)
    categories = list(data.keys())
    defenses = ["No Defense", "AttestMCP", "PTG-Only", "RTV-Only", "ReasoningGuard"]
    x = np.arange(len(categories))
    width = 0.15

    fig, ax = plt.subplots(figsize=(10, 4.5))
    for i, d in enumerate(defenses):
        vals = [data[cat].get(d, 0) for cat in categories]
        bars = ax.bar(x + i * width, vals, width, label=d, color=COLORS.get(d, "#333333"),
                      edgecolor="black", linewidth=0.3)

    ax.set_xticks(x + width * 2)
    ax.set_xticklabels(categories, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("ASR (%)", fontsize=11)
    ax.set_title("ASR by Attack Category", fontsize=12, fontweight="bold")
    ax.legend(fontsize=8, ncol=3, loc="upper right")
    ax.set_ylim(0, 100)

    plt.tight_layout()
    path = os.path.join(PLOT_DIR, "per_category.pdf")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")


def plot_ablation():
    data = run_ablation_experiment(mock_mode=True)
    variants = list(data.keys())
    asr = [data[v]["ASR"] for v in variants]
    t3_asr = [data[v]["T3_ASR"] for v in variants]

    fig, ax = plt.subplots(figsize=(9, 4.5))
    x = np.arange(len(variants))
    width = 0.35
    bars1 = ax.bar(x - width / 2, asr, width, label="T1 ASR", color="#1f77b4",
                   edgecolor="black", linewidth=0.5)
    bars2 = ax.bar(x + width / 2, t3_asr, width, label="T3 ASR", color="#d62728",
                   edgecolor="black", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels(variants, rotation=25, ha="right", fontsize=8)
    ax.set_ylabel("ASR (%)", fontsize=11)
    ax.set_title("Ablation Study", fontsize=12, fontweight="bold")
    ax.legend(fontsize=10)
    ax.set_ylim(0, 45)
    for bars in [bars1, bars2]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.5,
                    f"{h:.1f}", ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    path = os.path.join(PLOT_DIR, "ablation.pdf")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")


def plot_multi_model():
    data = run_multi_model_experiment(mock_mode=True)
    models = list(data.keys())
    x = np.arange(len(models))
    width = 0.25

    fig, ax = plt.subplots(figsize=(9, 4.5))
    no_def = [data[m]["No Defense"]["ASR"] for m in models]
    attest = [data[m]["AttestMCP"]["ASR"] for m in models]
    rg = [data[m]["ReasoningGuard"]["ASR"] for m in models]

    ax.bar(x - width, no_def, width, label="No Defense", color="#d62728",
           edgecolor="black", linewidth=0.5)
    ax.bar(x, attest, width, label="AttestMCP", color="#ff7f0e",
           edgecolor="black", linewidth=0.5)
    bars3 = ax.bar(x + width, rg, width, label="ReasoningGuard", color="#e377c2",
           edgecolor="black", linewidth=0.5)

    for bars in [ax.containers[0], ax.containers[1], ax.containers[2]]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 1,
                    f"{h:.1f}", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(models, fontsize=10)
    ax.set_ylabel("ASR (%)", fontsize=11)
    ax.set_title("Multi-Model ASR Comparison", fontsize=12, fontweight="bold")
    ax.legend(fontsize=10)
    ax.set_ylim(0, 85)

    plt.tight_layout()
    path = os.path.join(PLOT_DIR, "multi_model.pdf")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")


def main():
    print("Generating paper figures...")
    plot_main_asr()
    plot_t1_vs_t3()
    plot_per_category()
    plot_ablation()
    plot_multi_model()
    print(f"\nAll figures saved to {PLOT_DIR}/")


if __name__ == "__main__":
    main()