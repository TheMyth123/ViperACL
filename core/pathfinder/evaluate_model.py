"""
core/pathfinder/evaluate_model.py
Unified Multi-Engine Machine Learning Evaluator for ViperACL.

Provides empirical evaluation and benchmark evidence for FYP Chapter 5.3.3 across all 3
predictive pathfinding architectures on independent hold-out test datasets:
1. Random Forest (150 Bagged Trees)
2. LightGBM (Gradient Boosted Trees + TreeSHAP)
3. Path-Transformer (Deep Multi-Head Self-Attention)

Outputs:
- Comprehensive dataset statistics & class distributions
- Model-specific confusion matrices (ASCII, raw counts, TN/FP/FN/TP breakdowns)
- Full Scikit-Learn classification reports (Precision, Recall, F1, Support, Macro/Weighted Avg)
- Consolidated metric comparisons (Accuracy, Precision, Recall, F1, ROC-AUC)
- Inference latency and throughput benchmarks
- Publication-quality figures (300 DPI PNGs) saved to evaluation_results/
- Structured JSON and CSV exports for FYP documentation and empirical verification
"""

from __future__ import annotations

import csv
import json
import os
import sys
import time
from pathlib import Path

# Bootstrap project root to Python module path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Set non-interactive backend for headless figure generation
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

from core.logger import logger
from core.pathfinder.lgbm_evaluate import evaluate_lgbm_model
from core.pathfinder.rf_evaluate import evaluate_rf_model
from core.pathfinder.transformer_evaluate import evaluate_transformer_model


# Default output directory for all evaluation figures and data exports
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "evaluation_results"


def render_metric_row(name: str, rf_val: float, lgbm_val: float, trans_val: float, is_pct: bool = True, fmt_precision: int = 4) -> str:
    """Formats a comparative row across the three ML models."""
    if is_pct:
        rf_str = f"{rf_val * 100:6.2f}%"
        lgbm_str = f"{lgbm_val * 100:6.2f}%"
        trans_str = f"{trans_val * 100:6.2f}%"
    else:
        if fmt_precision == 1:
            rf_str = f"{rf_val:,.1f}"
            lgbm_str = f"{lgbm_val:,.1f}"
            trans_str = f"{trans_val:,.1f}"
        else:
            rf_str = f"{rf_val:7.4f}"
            lgbm_str = f"{lgbm_val:7.4f}"
            trans_str = f"{trans_val:7.4f}"

    return f"  │ {name:<26} │ {rf_str:^16} │ {lgbm_str:^16} │ {trans_str:^16} │"


def generate_confusion_matrix_plot(
    cm: np.ndarray,
    model_name: str,
    acc: float,
    f1: float,
    output_path: Path,
    palette_name: str = "Blues",
) -> None:
    """
    Generates a publication-quality 300-DPI confusion matrix heatmap with
    explicit True/False Positive/Negative labels, raw counts, and percentage annotations.
    """
    tn, fp, fn, tp = cm.ravel()
    total = float(cm.sum())

    plt.figure(figsize=(6.5, 5.5), dpi=300)
    plt.rcParams.update({"font.family": "sans-serif", "font.size": 11})

    # Custom formatted annotations for each cell
    labels = np.array([
        [f"TN\n{tn:,}\n({(tn/total)*100:.1f}%)", f"FP\n{fp:,}\n({(fp/total)*100:.1f}%)"],
        [f"FN\n{fn:,}\n({(fn/total)*100:.1f}%)", f"TP\n{tp:,}\n({(tp/total)*100:.1f}%)"],
    ])

    cmap = sns.color_palette(palette_name, as_cmap=True)
    ax = sns.heatmap(
        cm,
        annot=labels,
        fmt="",
        cmap=cmap,
        cbar=True,
        linewidths=1.5,
        linecolor="#E5E7EB",
        square=True,
        annot_kws={"size": 13, "weight": "bold"},
        xticklabels=["Fail (0)", "Pass (1)"],
        yticklabels=["Fail (0)", "Pass (1)"],
    )

    ax.set_title(
        f"ViperACL — {model_name} Confusion Matrix\n"
        f"Hold-Out Test Set (N={int(total)}) | Accuracy: {acc*100:.2f}% | F1: {f1*100:.2f}%\n",
        fontsize=12,
        fontweight="bold",
        pad=10,
    )
    ax.set_xlabel("Predicted Class", fontsize=11, fontweight="bold", labelpad=10)
    ax.set_ylabel("Actual Ground Truth Class", fontsize=11, fontweight="bold", labelpad=10)
    ax.tick_params(axis="both", which="major", labelsize=11)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()


def generate_comparative_metrics_plot(
    rf_res: dict,
    lgbm_res: dict,
    trans_res: dict,
    output_path: Path,
) -> None:
    """
    Generates a publication-grade grouped bar chart comparing the 5 primary metrics
    (Accuracy, Precision, Recall, F1-Score, ROC-AUC) across all three architectures.
    """
    metrics = ["Accuracy", "Precision", "Recall", "F1 Score", "ROC-AUC"]
    rf_scores = [rf_res["accuracy"] * 100, rf_res["precision"] * 100, rf_res["recall"] * 100, rf_res["f1"] * 100, rf_res["roc_auc"] * 100]
    lgbm_scores = [lgbm_res["accuracy"] * 100, lgbm_res["precision"] * 100, lgbm_res["recall"] * 100, lgbm_res["f1"] * 100, lgbm_res["roc_auc"] * 100]
    trans_scores = [trans_res["accuracy"] * 100, trans_res["precision"] * 100, trans_res["recall"] * 100, trans_res["f1"] * 100, trans_res["roc_auc"] * 100]

    x = np.arange(len(metrics))
    width = 0.26

    fig, ax = plt.subplots(figsize=(11.5, 6.5), dpi=300)
    plt.rcParams.update({"font.family": "sans-serif", "font.size": 10})

    # Modern color palette
    c_rf = "#2563EB"       # Royal Blue
    c_lgbm = "#059669"     # Emerald Green
    c_trans = "#7C3AED"    # Violet Purple

    rects1 = ax.bar(x - width, rf_scores, width, label="Random Forest (150 Trees)", color=c_rf, edgecolor="none", alpha=0.92)
    rects2 = ax.bar(x, lgbm_scores, width, label="LightGBM + TreeSHAP", color=c_lgbm, edgecolor="none", alpha=0.92)
    rects3 = ax.bar(x + width, trans_scores, width, label="Path-Transformer (Multi-Head)", color=c_trans, edgecolor="none", alpha=0.92)

    ax.set_ylabel("Performance Score (%)", fontsize=11, fontweight="bold")
    ax.set_title(
        "ViperACL Predictive Engine — Architecture Performance Benchmark\n"
        "FYP Chapter 5.3.3 Evaluation on Hold-Out Active Directory Telemetry (N=480)\n",
        fontsize=13,
        fontweight="bold",
        pad=14,
    )
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=11, fontweight="bold")
    ax.set_ylim(0, 116)
    ax.set_yticks(np.arange(0, 101, 10))
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f"{int(y)}%"))
    ax.grid(axis="y", linestyle="--", alpha=0.35, color="#9CA3AF")
    ax.set_axisbelow(True)

    # Add numeric labels on top of each bar
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(
                f"{height:.2f}%",
                xy=(rect.get_x() + rect.get_width() / 2, height),
                xytext=(0, 4),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8.5,
                fontweight="bold",
                rotation=0,
            )

    autolabel(rects1)
    autolabel(rects2)
    autolabel(rects3)

    ax.legend(
        loc="upper right",
        frameon=True,
        facecolor="#FFFFFF",
        edgecolor="#D1D5DB",
        fontsize=10,
        title="Model Architectures",
        title_fontsize=10,
    )

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()


def save_machine_readable_results(
    results: dict,
    output_dir: Path,
) -> dict[str, str]:
    """
    Saves all metrics, confusion matrices, classification reports, and dataset
    summaries into standardized JSON and CSV files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_files = {}

    # 1. Consolidated Metrics CSV
    csv_path = output_dir / "consolidated_metrics.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Model Architecture", "Test Accuracy (%)", "Precision Score (%)", "Recall Sensitivity (%)", "F1 Classification (%)", "ROC-AUC Score (%)", "Inference Time per Sample (ms)", "Throughput (samples/sec)"])
        for key, name in [("random_forest", "Random Forest"), ("lightgbm", "LightGBM"), ("transformer", "Path-Transformer")]:
            m = results[key]
            inf = m.get("inference_stats", {})
            writer.writerow([
                name,
                f"{m['accuracy']*100:.2f}",
                f"{m['precision']*100:.2f}",
                f"{m['recall']*100:.2f}",
                f"{m['f1']*100:.2f}",
                f"{m['roc_auc']*100:.2f}",
                f"{inf.get('avg_time_ms', 0):.4f}",
                f"{inf.get('samples_per_sec', 0):.1f}",
            ])
    generated_files["consolidated_metrics_csv"] = str(csv_path)

    # 2. Consolidated Metrics JSON
    json_metrics_path = output_dir / "consolidated_metrics.json"
    clean_metrics = {
        key: {
            "model_name": results[key]["model_name"],
            "accuracy": results[key]["accuracy"],
            "precision": results[key]["precision"],
            "recall": results[key]["recall"],
            "f1": results[key]["f1"],
            "roc_auc": results[key]["roc_auc"],
            "accuracy_pct": round(results[key]["accuracy"] * 100, 2),
            "precision_pct": round(results[key]["precision"] * 100, 2),
            "recall_pct": round(results[key]["recall"] * 100, 2),
            "f1_pct": round(results[key]["f1"] * 100, 2),
            "roc_auc_pct": round(results[key]["roc_auc"] * 100, 2),
            "inference_stats": results[key].get("inference_stats", {}),
        }
        for key in ["random_forest", "lightgbm", "transformer"]
    }
    with open(json_metrics_path, "w", encoding="utf-8") as f:
        json.dump(clean_metrics, f, indent=2)
    generated_files["consolidated_metrics_json"] = str(json_metrics_path)

    # 3. Confusion Matrices JSON
    cm_path = output_dir / "confusion_matrices.json"
    cm_data = {
        key: {
            "model_name": results[key]["model_name"],
            "raw_matrix": results[key]["confusion_matrix"].tolist() if isinstance(results[key]["confusion_matrix"], np.ndarray) else results[key]["confusion_matrix"],
            "true_negatives_tn": results[key]["tn"],
            "false_positives_fp": results[key]["fp"],
            "false_negatives_fn": results[key]["fn"],
            "true_positives_tp": results[key]["tp"],
            "total_test_samples": results[key]["tn"] + results[key]["fp"] + results[key]["fn"] + results[key]["tp"],
            "tn_pct": round((results[key]["tn"] / (results[key]["tn"] + results[key]["fp"] + results[key]["fn"] + results[key]["tp"])) * 100, 2),
            "fp_pct": round((results[key]["fp"] / (results[key]["tn"] + results[key]["fp"] + results[key]["fn"] + results[key]["tp"])) * 100, 2),
            "fn_pct": round((results[key]["fn"] / (results[key]["tn"] + results[key]["fp"] + results[key]["fn"] + results[key]["tp"])) * 100, 2),
            "tp_pct": round((results[key]["tp"] / (results[key]["tn"] + results[key]["fp"] + results[key]["fn"] + results[key]["tp"])) * 100, 2),
        }
        for key in ["random_forest", "lightgbm", "transformer"]
    }
    with open(cm_path, "w", encoding="utf-8") as f:
        json.dump(cm_data, f, indent=2)
    generated_files["confusion_matrices_json"] = str(cm_path)

    # 4. Classification Reports JSON
    reports_path = output_dir / "classification_reports.json"
    reports_data = {
        key: {
            "model_name": results[key]["model_name"],
            "report_dict": results[key].get("classification_report_dict", {}),
            "report_text": results[key].get("classification_report", ""),
        }
        for key in ["random_forest", "lightgbm", "transformer"]
    }
    with open(reports_path, "w", encoding="utf-8") as f:
        json.dump(reports_data, f, indent=2)
    generated_files["classification_reports_json"] = str(reports_path)

    # 5. Dataset Summary JSON
    ds_path = output_dir / "dataset_summary.json"
    dataset_summary = {
        "dataset_name": "Active Directory Synthetic Attack Telemetry Hold-Out Test Set",
        "total_test_samples": results["random_forest"]["dataset_info"]["total_samples"],
        "num_classes": results["random_forest"]["dataset_info"]["num_classes"],
        "class_labels": results["random_forest"]["dataset_info"]["class_labels"],
        "class_distribution": results["random_forest"]["dataset_info"]["class_counts"],
        "class_percentages": results["random_forest"]["dataset_info"]["class_percentages"],
        "hold_out_test_paths": {
            "random_forest": "data/rf_synthetic_testing.csv",
            "lightgbm": "data/lgbm_synthetic_testing.csv",
            "transformer": "data/transformer_synthetic_testing.jsonl",
        },
    }
    with open(ds_path, "w", encoding="utf-8") as f:
        json.dump(dataset_summary, f, indent=2)
    generated_files["dataset_summary_json"] = str(ds_path)

    # 6. Comprehensive Evaluation Summary JSON
    summary_path = output_dir / "evaluation_summary.json"
    comprehensive_summary = {
        "metadata": {
            "title": "ViperACL Multi-Engine ML Model Evaluation (FYP Chapter 5.3.3)",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "device": "CPU / GPU Telemetry Benchmark",
        },
        "dataset": dataset_summary,
        "metrics": clean_metrics,
        "confusion_matrices": cm_data,
        "classification_reports": reports_data,
    }
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(comprehensive_summary, f, indent=2)
    generated_files["evaluation_summary_json"] = str(summary_path)

    return generated_files


def evaluate_all_models(
    verbose: bool = True,
    output_dir: Path | str | None = None,
) -> dict[str, dict]:
    """
    Executes benchmark evaluation across Random Forest, LightGBM, and Path-Transformer
    against the independent hold-out test dataset, presenting:
    1. Comprehensive test dataset information
    2. Model-specific evaluation blocks (metrics, CM, TN/FP/FN/TP, classification report)
    3. Consolidated comparison tables
    4. Publication-grade figures (300 DPI) and machine-readable data exports.
    """
    import io

    out_dir = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    report_buf = io.StringIO()

    def log_print(msg: str = ""):
        report_buf.write(msg + "\n")
        if verbose:
            print(msg)

    log_print("=" * 80)
    log_print("     VIPERACL PREDICTIVE ENGINE — UNIFIED MULTI-MODEL BENCHMARK")
    log_print("                 FYP Chapter 5.3.3 Empirical Evaluation")
    log_print("=" * 80)
    log_print("  Evaluating models on independent hold-out test datasets...\n")

    # Evaluate individual models on independent test sets
    rf_results = evaluate_rf_model(verbose=False)
    lgbm_results = evaluate_lgbm_model(verbose=False)
    trans_results = evaluate_transformer_model(verbose=False)

    ds_info = rf_results["dataset_info"]
    total_samples = ds_info["total_samples"]
    fail_count = ds_info["class_counts"]["Fail (0)"]
    pass_count = ds_info["class_counts"]["Pass (1)"]

    # Section 1: Test Dataset Information
    log_print("=" * 80)
    log_print("1. INDEPENDENT HOLD-OUT TEST DATASET SPECIFICATIONS")
    log_print("=" * 80)
    log_print(f"  • Total Number of Test Samples  : {total_samples:,} samples")
    log_print(f"  • Number of Target Classes      : {ds_info['num_classes']} classes ({', '.join(ds_info['class_labels'])})")
    log_print(f"  • Class 0 [Fail / Impossible]   : {fail_count:>4} samples ({ds_info['class_percentages']['Fail (0)']:.2f}%)")
    log_print(f"  • Class 1 [Pass / Viable]       : {pass_count:>4} samples ({ds_info['class_percentages']['Pass (1)']:.2f}%)")
    log_print("  • Verification Datasets         : data/rf_synthetic_testing.csv")
    log_print("                                    data/lgbm_synthetic_testing.csv")
    log_print("                                    data/transformer_synthetic_testing.jsonl")
    log_print("=" * 80)
    log_print()

    # Section 2: Model-Specific Results Blocks
    for res in [rf_results, lgbm_results, trans_results]:
        name_upper = res["model_name"].upper()
        tn, fp, fn, tp = res["tn"], res["fp"], res["fn"], res["tp"]
        inf = res["inference_stats"]

        log_print("=" * 80)
        log_print(f"{name_upper} — HOLD-OUT TEST RESULTS")
        log_print("=" * 80)
        log_print(f"[*] Dataset Context: {total_samples} samples | Class 0: {fail_count} ({fail_count/total_samples*100:.1f}%) | Class 1: {pass_count} ({pass_count/total_samples*100:.1f}%)")
        log_print("-" * 80)
        log_print("  CLASSIFICATION PERFORMANCE METRICS:")
        log_print("-" * 80)
        log_print(f"  • Test Accuracy       : {res['accuracy']*100:6.2f}%")
        log_print(f"  • Precision Score     : {res['precision']*100:6.2f}%")
        log_print(f"  • Recall (Sensitivity): {res['recall']*100:6.2f}%")
        log_print(f"  • F1-Score            : {res['f1']*100:6.2f}%")
        log_print(f"  • ROC-AUC Score       : {res['roc_auc']*100:6.2f}%")
        log_print("-" * 80)
        log_print("  CONFUSION MATRIX & QUADRANT BREAKDOWN:")
        log_print("-" * 80)
        log_print("  Raw Matrix (2x2):")
        log_print(f"    [[{tn:>4}, {fp:>4}],")
        log_print(f"     [{fn:>4}, {tp:>4}]]\n")
        log_print("  Quadrant Breakdown:")
        log_print(f"    • True Negatives  (TN) : {tn:>4}  ({tn/total_samples*100:5.2f}%)  [Correctly identified impossible paths]")
        log_print(f"    • False Positives (FP) : {fp:>4}  ({fp/total_samples*100:5.2f}%)  [False alarms / over-optimistic paths]")
        log_print(f"    • False Negatives (FN) : {fn:>4}  ({fn/total_samples*100:5.2f}%)  [Missed viable attack paths]")
        log_print(f"    • True Positives  (TP) : {tp:>4}  ({tp/total_samples*100:5.2f}%)  [Correctly validated viable paths]")
        log_print(f"    • Total Test Samples   : {total_samples:>4}  (100.00%)  [TN + FP + FN + TP = {tn + fp + fn + tp}]")
        log_print("-" * 80)
        log_print("  SKLEARN CLASSIFICATION REPORT:")
        log_print("-" * 80)
        log_print(res["classification_report"].rstrip())
        log_print("-" * 80)
        log_print("  INFERENCE LATENCY & THROUGHPUT:")
        log_print("-" * 80)
        log_print(f"  • Total Prediction Time : {inf['total_time_ms']:.2f} ms")
        log_print(f"  • Average Time / Sample : {inf['avg_time_ms']:.4f} ms ({inf['samples_per_sec']:,.1f} samples/sec)")
        log_print("=" * 80)
        log_print()

    # Section 3: Consolidated Benchmark Table
    log_print("=" * 80)
    log_print("  CONSOLIDATED CLASSIFICATION & GENERALIZATION BENCHMARKS")
    log_print("=" * 80)
    log_print("  ┌────────────────────────────┬──────────────────┬──────────────────┬──────────────────┐")
    log_print("  │ Metric                     │  Random Forest   │     LightGBM     │ Path-Transformer │")
    log_print("  ├────────────────────────────┼──────────────────┼──────────────────┼──────────────────┤")
    log_print(render_metric_row("Test Accuracy", rf_results["accuracy"], lgbm_results["accuracy"], trans_results["accuracy"]))
    log_print(render_metric_row("Precision Score", rf_results["precision"], lgbm_results["precision"], trans_results["precision"]))
    log_print(render_metric_row("Recall (Sensitivity)", rf_results["recall"], lgbm_results["recall"], trans_results["recall"]))
    log_print(render_metric_row("F1 Classification", rf_results["f1"], lgbm_results["f1"], trans_results["f1"]))
    log_print(render_metric_row("ROC-AUC Score", rf_results["roc_auc"], lgbm_results["roc_auc"], trans_results["roc_auc"]))
    log_print("  ├────────────────────────────┼──────────────────┼──────────────────┼──────────────────┤")
    log_print(render_metric_row("Avg Latency / Sample (ms)", rf_results["inference_stats"]["avg_time_ms"], lgbm_results["inference_stats"]["avg_time_ms"], trans_results["inference_stats"]["avg_time_ms"], is_pct=False, fmt_precision=4))
    log_print(render_metric_row("Throughput (samples/sec)", rf_results["inference_stats"]["samples_per_sec"], lgbm_results["inference_stats"]["samples_per_sec"], trans_results["inference_stats"]["samples_per_sec"], is_pct=False, fmt_precision=1))
    log_print("  └────────────────────────────┴──────────────────┴──────────────────┴──────────────────┘")
    log_print("=" * 80)

    # 4. Generate Figures
    rf_cm_path = out_dir / "confusion_matrix_rf.png"
    lgbm_cm_path = out_dir / "confusion_matrix_lgbm.png"
    trans_cm_path = out_dir / "confusion_matrix_transformer.png"
    comp_plot_path = out_dir / "comparative_model_metrics.png"

    generate_confusion_matrix_plot(rf_results["confusion_matrix"], "Random Forest", rf_results["accuracy"], rf_results["f1"], rf_cm_path, palette_name="Blues")
    generate_confusion_matrix_plot(lgbm_results["confusion_matrix"], "LightGBM + TreeSHAP", lgbm_results["accuracy"], lgbm_results["f1"], lgbm_cm_path, palette_name="crest")
    generate_confusion_matrix_plot(trans_results["confusion_matrix"], "Path-Transformer", trans_results["accuracy"], trans_results["f1"], trans_cm_path, palette_name="Purples")
    generate_comparative_metrics_plot(rf_results, lgbm_results, trans_results, comp_plot_path)

    # 5. Save Machine-Readable JSON & CSV Files
    results_map = {
        "random_forest": rf_results,
        "lightgbm": lgbm_results,
        "transformer": trans_results,
    }
    saved_files = save_machine_readable_results(results_map, out_dir)
    saved_files["confusion_matrix_rf"] = str(rf_cm_path)
    saved_files["confusion_matrix_lgbm"] = str(lgbm_cm_path)
    saved_files["confusion_matrix_transformer"] = str(trans_cm_path)
    saved_files["comparative_model_metrics"] = str(comp_plot_path)

    # Save full text evaluation report
    report_file_path = out_dir / "evaluation_report.txt"
    with open(report_file_path, "w", encoding="utf-8") as f:
        f.write(report_buf.getvalue())
    saved_files["evaluation_report_txt"] = str(report_file_path)

    # Structured audit logging
    logger.info(
        category="PATHFINDER",
        action="pathfinder.evaluation.completed",
        message="Multi-engine predictive ML evaluation and FYP Chapter 5.3.3 benchmark generated successfully.",
        details={
            "output_dir": str(out_dir),
            "test_samples": total_samples,
            "rf_accuracy": rf_results["accuracy"],
            "lgbm_accuracy": lgbm_results["accuracy"],
            "transformer_accuracy": trans_results["accuracy"],
            "figures_count": 4,
        },
        source="core.pathfinder.evaluate_model",
    )

    log_print(f"\n[✓] Generated Publication-Grade Figures & Data Exports in: {out_dir.relative_to(PROJECT_ROOT)}")
    log_print(f"  • Confusion Matrix (Random Forest)   : {rf_cm_path.name}")
    log_print(f"  • Confusion Matrix (LightGBM)        : {lgbm_cm_path.name}")
    log_print(f"  • Confusion Matrix (Path-Transformer): {trans_cm_path.name}")
    log_print(f"  • Comparative Metrics Benchmark Plot : {comp_plot_path.name}")
    log_print("  • Consolidated Metrics CSV & JSON    : consolidated_metrics.csv, consolidated_metrics.json")
    log_print("  • Confusion Matrices JSON            : confusion_matrices.json")
    log_print("  • Classification Reports JSON        : classification_reports.json")
    log_print("  • Dataset Summary JSON               : dataset_summary.json")
    log_print("  • Full Evaluation Text Report        : evaluation_report.txt")
    log_print("  • Comprehensive Summary JSON         : evaluation_summary.json")
    log_print("=" * 80)
    log_print("[✓] Multi-model evaluation and benchmark comparison complete.\n")

    return results_map


# Backwards compatibility aliases
evaluate_predictive_model = evaluate_all_models
evaluate_rf_model_compat = evaluate_rf_model


if __name__ == "__main__":
    evaluate_all_models(verbose=True)

