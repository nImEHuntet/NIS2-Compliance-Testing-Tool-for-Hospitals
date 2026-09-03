# NIS2 Healthcare Compliance Assessment Tool

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Status](https://img.shields.io/badge/status-research%20prototype-green.svg)

A transparent, deterministic, **locally-run** self-assessment tool that measures a healthcare organization's readiness for the EU **NIS2 Directive** (Directive (EU) 2022/2555). It scores an organization against **16 Risk Management Measures (RMMs)** and **30 evidence-weighted questions** mapped directly to NIS2 Article 21 and the Irish NCSC's RMM taxonomy, and then generates a board-ready report with a maturity tier, a prioritized gap analysis, and a **30-60-90-day remediation roadmap**.

It runs entirely on your own machine, **never ingests patient or production data**, and only *references* evidence (e.g., a policy ID). This means that it stays clear of GDPR concerns and can be run inside a segregated clinical network.

> Developed as the artifact for an MSc Cybersecurity thesis (*NIS2 Compliance and Cybersecurity Resilience in Critical Healthcare Infrastructure*, Munster Technological University). Tailored to healthcare but re-parameterisable for other NIS2 sectors.

---

## Key features

- **Regulator-aligned:** 16 RMMs map 1:1 to the NCSC's published Risk Management Measures and back to NIS2 Articles 21 / 20 / 23.
- **Evidence-weighted scoring:** every answer is scaled by an *evidence-assurance* multiplier, so an unproven "Yes" scores no better than a well-evidenced "Partial".
- **Deterministic & auditable:** no AI, no black box. Any score can be reconstructed by hand.
- **Board-ready PDF report:** executive risk statement, radar/bar charts, prioritized remediation with owners, 30-60-90 roadmap, per-system RTO/RPO recovery objectives, and 24-hour incident-reporting readiness.
- **Privacy by design:** local-only, no network calls, no sensitive data ingested.
- **Reproducible:** every assessment is defined by a JSON dataset and regenerates identical output.

---

## Repository structure

```
.
├── LICENSE                     # MIT
├── README.md                   # this file
├── NIS2_Compliance_Test.py     # the assessment tool (single file)
├── run_all_cases.py            # batch helper: runs every example dataset
├── JSON Examples/              # example assessment datasets
│   ├── regional_hospital_assessment.json     # evidence-referenced example (Tier 2)
│   ├── teaching_hospital_assessment.json      # synthetic profile (Tier 3)
│   └── specialised_clinic_assessment.json     # synthetic profile (Tier 1)
└── Outputs/                    # generated charts, CSVs and PDF reports
```

---

## Requirements

- Python 3.8+
- `matplotlib`, `numpy`, `reportlab`

```bash
pip install matplotlib numpy reportlab
```

---

## Usage

### 1. Run all example datasets at once (quickest start)

```bash
python run_all_cases.py
```

This reads every dataset in `JSON Examples/`, prints a score summary, and writes each case's charts, CSV, and PDF report. In addition, it writes two cross-case comparison charts to `Outputs/`.

### 2. Assess a single organization from a dataset

```bash
python NIS2_Compliance_Test.py --responses "JSON Examples/regional_hospital_assessment.json"
```

Prints the overall score, maturity tier, and per-RMM breakdown to the terminal, and writes a CSV, two charts, and a PDF report to the current folder.

### 3. Interactive assessment (answer the 30 questions yourself)

```bash
python NIS2_Compliance_Test.py --org "My Hospital" --org-size Medium
```

You'll be prompted for each question's response (Y/P/N), an evidence reference, and an assurance level.

### Command-line options

| Flag | Description | Default |
|---|---|---|
| `--responses PATH` | Score from a saved JSON responses/evidence dataset | - |
| `--org NAME` | Organisation name | `Regional Hospital` |
| `--org-size SIZE` | `Small` / `Medium` / `Large` | `Medium` |
| `--target PCT` | Target maturity percentage | `75` (Tier 3) |
| `--schema PATH` | Load an external questionnaire schema (JSON) | built-in |
| `--demo` | Run a non-interactive synthetic demo profile | - |
| `--sensitivity` | Report the score at Partial = 0.5 / 1.0 / 2.0 | - |
| `--partial VALUE` | Override the "Partial" score value | `1.0` |

---

## Outputs

For each assessment, the tool produces:

- **PDF report** - cover (score + tier), "how to read this score", executive risk statement, RMM bar chart, category radar chart, prioritized remediation table (owner / due / evidence), 30-60-90 day roadmap, critical-system RTO/RPO table + DR test schedule, 24-hour early-warning readiness, consistency checks, and a per-question appendix.
- **CSV** - a per-question audit trail (RMM, article, weight, response, assurance, evidence, score).
- **PNG charts** - per-RMM implementation scores (bar) and a maturity profile (radar).

---

## Dataset format

An assessment dataset is a small JSON file. Each answer records the response, the assurance level, and a **reference** to the supporting evidence (never the evidence itself):

```json
{
  "org": "Regional Hospital",
  "org_size": "Medium",
  "date": "2026-06-09",
  "data_source": "On-site NIS2 assessment - evidence-referenced responses",
  "answers": [
    {"qid": 17, "response": "No",  "assurance": "High",
     "evidence": "IAM coverage report IAM-RPT-2026-04: MFA on VPN only (62% of accounts)"},
    {"qid": 27, "response": "Yes", "assurance": "High",
     "evidence": "Incident Reporting Procedure IRP-PROC-007 v1.0; test submission TEST-EW-2026-01"}
  ]
}
```

- `response` ∈ `Yes` | `Partial` | `No`
- `assurance` ∈ `None` | `Low` | `Medium` | `High`
- `qid` = question number 1–30 (see the questionnaire in `NIS2_Compliance_Test.py`)

Copy an example from `JSON Examples/` and edit it to assess your own organization.

---

## How scoring works

Each question is scored as **`response × weight × assurance`**:

| Response | Value | | Assurance | Multiplier |
|---|---|---|---|---|
| Yes | 4 | | High | 1.0 |
| Partial | 1 | | Medium | 0.8 |
| No | 0 | | Low | 0.5 |
| | | | None | 0.0 |

Critical controls (MFA, 24-hour reporting) carry a higher weight. The overall percentage is the assurance-adjusted weighted total divided by the maximum achievable, mapped to a maturity tier:

| Tier | Band | Meaning |
|---|---|---|
| **Tier 1 - Initial** | 0–49% | Non-compliant; ad-hoc, reactive |
| **Tier 2 - Managed** | 50–74% | Foundational controls; material gaps |
| **Tier 3 - Defined** | 75–89% | Documented, implemented, tested. This is the **target for essential entities** |
| **Tier 4 - Optimised** | 90–100% | Proactive, threat-led; beyond the baseline |

---

## Example results

Running the three bundled datasets demonstrates that the model differentiates cleanly across the maturity spectrum:

| Organisation | Overall | Tier |
|---|---|---|
| Specialised Diagnostic Clinic (heavily outsourced) | 17.9% | Tier 1 - Initial |
| Regional Hospital | 56.2% | Tier 2 - Managed |
| Metropolitan Teaching Hospital | 83.5% | Tier 3 - Defined |

The Regional Hospital dataset is an evidence-referenced example; the Teaching Hospital and Specialized Clinic are **transparently labeled synthetic profiles** (as stated in each file's `data_source`) constructed from public benchmarks for illustration.

---

## Privacy & data handling

The tool processes **no patient or production data**. Assessors enter responses and *references* to evidence (document identifiers), which stay on the local machine. There are no network calls, and nothing is uploaded to any external or cloud service.

## Disclaimer

This is a **readiness self-assessment aid**, not a certification, an audit, or legal advice. Scores are relative indicators to guide prioritization, not a definitive statement of legal compliance. NIS2 and its national transposition are evolving; verify requirements against current official guidance (e.g. the Irish NCSC and ENISA) and seek professional advice for compliance decisions.

## How to cite

> A. Karmokar, *NIS2 Compliance and Cybersecurity Resilience in Critical Healthcare Infrastructure*, MSc Cybersecurity thesis, Munster Technological University, 2026.

## License

Released under the [MIT License](LICENSE). © 2026 Ayushmaan Karmokar.
