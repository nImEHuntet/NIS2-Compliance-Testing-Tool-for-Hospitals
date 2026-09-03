#!/usr/bin/env python3
"""
run_all_cases.py  -  Batch reproducibility helper for the NIS2 assessment tool.

Runs NIS2_Compliance_Test.py against every example dataset and writes the score
summary, per-case charts, per-case PDF reports and CSV audit trails, plus two
cross-case comparison charts.

Layout-aware: it looks for the datasets in "JSON Examples/" first (falling back
to the script's own folder), and writes everything to "Outputs/". Just run:

    python run_all_cases.py

Requires: matplotlib, numpy, reportlab  (see requirements.txt)
"""

import os
import json
import datetime
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "NIS2_Compliance_Test.py")
INPUT_DIRS = [os.path.join(HERE, "JSON Examples"), HERE]   # search order
OUT = os.path.join(HERE, "Outputs")
os.makedirs(OUT, exist_ok=True)


def find_dataset(fn):
    for d in INPUT_DIRS:
        p = os.path.join(d, fn)
        if os.path.exists(p):
            return p
    raise FileNotFoundError(f"Could not find {fn} in {INPUT_DIRS}")


# Load the tool as a module regardless of its filename.
spec = importlib.util.spec_from_file_location("nis2_tool", TOOL)
nis2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nis2)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

CASES = [
    "regional_hospital_assessment.json",
    "teaching_hospital_assessment.json",
    "specialised_clinic_assessment.json",
]

all_scores = {}
summary = {}

for fn in CASES:
    with open(find_dataset(fn), encoding="utf-8") as f:
        data = json.load(f)
    a = nis2.Assessment(org_name=data["org"], org_size=data.get("org_size", "Medium"))
    a.apply_answers(data.get("answers", []), data.get("data_source"))
    try:
        a.assessment_date = datetime.datetime.strptime(data["date"], "%Y-%m-%d")
    except Exception:
        pass
    pct, tier = a.calculate_overall()
    all_scores[data["org"]] = a.rmm_scores()
    summary[data["org"]] = (pct, tier, a.tiers[tier]["label"])
    slug = data["org"].replace(" ", "_")
    a.generate_bar_chart(os.path.join(OUT, slug + "_bar.png"))
    a.generate_radar_chart(os.path.join(OUT, slug + "_radar.png"))
    a.export_csv(os.path.join(OUT, slug + "_assessment.csv"))
    a.generate_pdf(os.path.join(OUT, slug + "_report.pdf"))
    print("%-34s %5.1f%%  %s - %s" % (data["org"], pct, tier, a.tiers[tier]["label"]))

# ---- Cross-case comparison chart ----
rmm_ids = sorted(next(iter(all_scores.values())).keys())
orgs = list(all_scores.keys())
cols = ["#1a237e", "#2e7d32", "#c62828"]
x = np.arange(len(rmm_ids)); w = 0.26
fig, ax = plt.subplots(figsize=(15, 7))
for k, o in enumerate(orgs):
    ax.bar(x + (k - 1) * w, [all_scores[o][r] for r in rmm_ids], w,
           label=o, color=cols[k % len(cols)], edgecolor="black", linewidth=0.4)
ax.axhline(75, color="green", ls="--", lw=1, label="Tier 3 target (75%)")
ax.axhline(50, color="orange", ls="--", lw=1, label="Tier 2 threshold (50%)")
ax.set_ylim(0, 105); ax.set_ylabel("Implementation (%)")
ax.set_title("Cross-Case Comparison of RMM Implementation Scores", pad=14)
ax.set_xticks(x); ax.set_xticklabels(rmm_ids, rotation=45, ha="right", fontsize=8)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=5, fontsize=8, frameon=True)
plt.tight_layout(); plt.savefig(os.path.join(OUT, "cross_case_comparison.png"), dpi=200, bbox_inches="tight"); plt.close()

# ---- Overall readiness comparison chart ----
o2 = list(summary.keys()); p = [summary[o][0] for o in o2]
bc = ["#c62828" if v < 50 else "#f9a825" if v < 75 else "#2e7d32" for v in p]
fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar([o.replace(" ", "\n") for o in o2], p, color=bc, edgecolor="black")
ax.axhline(75, color="green", ls="--", lw=1.2, label="Tier 3 - Defined/Compliant (75%)")
ax.axhline(50, color="orange", ls="--", lw=1.2, label="Tier 2 - Managed (50%)")
ax.set_ylim(0, 100); ax.set_ylabel("Overall NIS2 readiness (%)")
ax.set_title("Overall NIS2 Readiness by Case Study")
for bar, v in zip(bars, p):
    ax.text(bar.get_x() + bar.get_width() / 2, v + 1.5, "%.1f%%" % v, ha="center", fontweight="bold")
ax.legend(fontsize=9)
plt.tight_layout(); plt.savefig(os.path.join(OUT, "overall_comparison.png"), dpi=200); plt.close()

print("\nDone. All outputs written to ./Outputs/")
