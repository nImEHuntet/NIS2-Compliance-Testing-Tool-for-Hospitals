#!/usr/bin/env python3
"""
NIS2 Healthcare Compliance Assessment Tool
Author: Ayushmaan Karmokar
Student ID: R00276128
For the MSc Cyber Security program thesis at the Munster Technological University (MTU), Ireland.
Date: 07-04-2026
License: MIT

Goal
-------
Assesses a healthcare organization's compliance with the EU NIS2 Directive's
risk-management measures (Article 21) and incident-reporting duties
(Article 23). The assessment is structured as 30 weighted yes/partial/no
questions mapped onto 16 "RMM" (Risk Management Measure) domains grouped
into Governance / Policy / Technical / Incident / Continuity categories.

Each answer is scaled by a question weight reflecting how critical the
control is under NIS2, and an evidence-assurance factor reflecting how
well the answer is substantiated (an unsupported "Yes" counts for less than
one backed by evidence). Domain and overall scores are converted into a
0-100% maturity percentage and mapped onto a 4-tier maturity model.

The tool can run interactively (asking the assessor questions), replay a
previously captured evidence dataset (--responses), or generate a synthetic
demo profile (--demo) for testing/demonstration. Outputs are a CSV of raw
answers, bar/radar charts of domain scores, and a full PDF report.
Report includes methodology, executive risk statement, prioritized remediation plan,
30/60/90-day road map, business-continuity RTO/RPO tables and incident-
reporting readiness. It is intended for hospital leadership and auditors.
"""

import json
import csv
import sys
import argparse
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import math
import matplotlib.pyplot as plt
import numpy as np
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import tempfile
import os


# Configuration
# Raw points awarded per answer, before weighting/assurance are applied.
# 'Partial' is configurable (see --partial / --sensitivity in the
# CLI.) This is because of how harshly a partial control should be scored,
# run_sensitivity() shows how the overall % moves if it is
# treated as closer to "No" (e.g. 0.5) or closer to "Yes" (e.g. 2.0).
DEFAULT_SCORING = {
    'Yes': 4.0,
    'Partial': 1.0,
    'No': 0.0
}

# Multiplier applied to a question's raw score based on how well the answer
# is evidenced. An unsupported "Yes" (assurance='None') contributes nothing,
# while a fully-documented "Yes" (assurance='High') contributes in full. This
# stops self-reported compliance with no proof from inflating the score.
ASSURANCE_WEIGHTS = {
    'None': 0.0,
    'Low': 0.5,
    'Medium': 0.8,
    'High': 1.0
}

# Maturity model the overall percentage is mapped onto. Tier 3 (75%) is the
# expected minimum for an "essential entity" under NIS2; Tier 4 is aspirational, not required.
DEFAULT_MATURITY_TIERS = {
    'Tier 1': {'range': (0.0, 49.99), 'label': 'Initial (Non-Compliant)'},
    'Tier 2': {'range': (50.0, 74.99), 'label': 'Managed (Foundational)'},
    'Tier 3': {'range': (75.0, 89.99), 'label': 'Defined (Compliant)'},
    'Tier 4': {'range': (90.0, 100.0), 'label': 'Optimized (Mature)'},
}

# Embedded default schema
# This is the fallback assessment content used when no --schema file is
# passed on the CLI. It defines:
#   - rmm_definitions: the 16 Risk Management Measure domains (id/name/
#     category/description) that questions and remediation are grouped by.
#   - questions: the 30 scored questions, each tied to an RMM, a NIS2 article
#     reference (for traceability/audit) and a weight.
#   - recommendations: short, legacy one-line fixes (superseded by the richer
#     DEFAULT_REMEDIATION playbook below, but kept as a fallback/description).
DEFAULT_SCHEMA = {
    "metadata": {
        "title": "NIS2 Healthcare Assessment",
        "version": "1.0"
    },
    "rmm_definitions": [
        {"id": "RMM001", "name": "Registration", "category": "Governance", "desc": "NCSC Registration"},
        {"id": "RMM002", "name": "Board Governance", "category": "Governance", "desc": "Oversight & Training"},
        {"id": "RMM003", "name": "Security Policy", "category": "Policy", "desc": "ISMS Documentation"},
        {"id": "RMM004", "name": "Risk Assessment", "category": "Policy", "desc": "Asset & Risk Analysis"},
        {"id": "RMM005", "name": "Measurement", "category": "Policy", "desc": "Audit & Review"},
        {"id": "RMM006", "name": "Cyber Hygiene", "category": "Technical", "desc": "Patching & Backups"},
        {"id": "RMM007", "name": "Asset Mgmt", "category": "Technical", "desc": "Inventory"},
        {"id": "RMM008", "name": "HR Security", "category": "Technical", "desc": "Checks & Access"},
        {"id": "RMM009", "name": "Access Control", "category": "Technical", "desc": "MFA & Least Privilege"},
        {"id": "RMM010", "name": "Physical Sec", "category": "Technical", "desc": "Datacenter Security"},
        {"id": "RMM011", "name": "Cryptography", "category": "Technical", "desc": "Encryption"},
        {"id": "RMM012", "name": "Supply Chain", "category": "Technical", "desc": "Vendor Risk"},
        {"id": "RMM013", "name": "Secure Dev", "category": "Technical", "desc": "Vulnerability Mgmt"},
        {"id": "RMM014", "name": "Incident Resp", "category": "Incident", "desc": "IR Plan & Testing"},
        {"id": "RMM015", "name": "Reporting", "category": "Incident", "desc": "NCSC Notification"},
        {"id": "RMM016", "name": "Continuity", "category": "Continuity", "desc": "BCP & DR"}
    ],
    "questions": [
        # (id, rmm, section, text, article_ref, weight, evidence_required)
        [1, "RMM001", "Governance", "Is there a designated officer for NIS2 compliance?", "Art.20(1)", 1.0, True],
        [2, "RMM002", "Governance", "Does the board explicitly approve cyber measures?", "Art.20(1)", 1.5, True],
        [3, "RMM002", "Governance", "Is there an approved cyber budget for 18 months?", "Art.20(1)", 1.0, True],
        [4, "RMM002", "Governance", "Do board members undergo mandatory cyber training?", "Art.20(2)", 1.0, True],
        [5, "RMM003", "Policy", "Is there a documented Security Policy (ISMS)?", "Art.21(2)(a)", 1.5, True],
        [6, "RMM003", "Policy", "Does policy cover all NIS2 risk areas?", "Art.21(2)", 1.0, True],
        [7, "RMM004", "Policy", "Are risk assessments conducted annually?", "Art.21(2)(a)", 1.5, True],
        [8, "RMM004", "Policy", "Are critical assets (e.g., EHR) formally identified?", "Art.21(2)(a)", 1.0, True],
        [9, "RMM005", "Policy", "Are measures audited/tested annually?", "Art.21(2)(f)", 1.0, True],
        [10, "RMM005", "Policy", "Is there a process to update measures post-incident?", "Art.21(2)(a)", 1.0, True],
        [11, "RMM006", "Technical", "Is patching performed within defined SLAs?", "Art.21(2)(e)", 1.5, True],
        [12, "RMM006", "Technical", "Are backups tested for restorability annually?", "Art.21(2)(c)", 1.5, True],
        [13, "RMM006", "Technical", "Is cyber hygiene training mandatory for all staff?", "Art.21(2)(g)", 1.0, True],
        [14, "RMM007", "Technical", "Is the asset inventory up-to-date?", "Art.21(2)(i)", 1.0, True],
        [15, "RMM008", "Technical", "Are background checks performed for sensitive roles?", "Art.21(2)(i)", 1.0, True],
        [16, "RMM008", "Technical", "Are access rights revoked immediately upon exit?", "Art.21(2)(i)", 1.0, True],
        [17, "RMM009", "Technical", "Is MFA enforced for ALL remote/admin access?", "Art.21(2)(j)", 2.0, True],
        [18, "RMM009", "Technical", "Is 'Least Privilege' strictly enforced?", "Art.21(2)(j)", 1.0, True],
        [19, "RMM010", "Technical", "Are physical server rooms secured?", "Art.21(2)", 1.0, False],
        [20, "RMM011", "Technical", "Is patient data encrypted at rest?", "Art.21(2)(h)", 1.5, True],
        [21, "RMM011", "Technical", "Is data encrypted in transit (TLS)?", "Art.21(2)(h)", 1.0, True],
        [22, "RMM012", "Technical", "Do supplier contracts include security SLAs?", "Art.21(2)(d)", 1.5, True],
        [23, "RMM012", "Technical", "Are critical vendors risk-assessed?", "Art.21(2)(d)", 1.0, True],
        [24, "RMM013", "Technical", "Is security built into system acquisition?", "Art.21(2)(e)", 1.0, True],
        [25, "RMM014", "Incident", "Is there a documented Incident Response Plan?", "Art.21(2)(b)", 1.5, True],
        [26, "RMM014", "Incident", "Has the IRP been tested (tabletop) in 12 months?", "Art.21(2)(b)", 1.0, True],
        [27, "RMM015", "Incident", "Can you submit an 'Early Warning' within 24h?", "Art.23(3)", 2.0, True],
        [28, "RMM015", "Incident", "Are detection mechanisms (IDS/SIEM) in place?", "Art.21(2)(b)", 1.0, True],
        [29, "RMM016", "Continuity", "Is there a Business Continuity Plan with RTOs?", "Art.21(2)(c)", 1.5, True],
        [30, "RMM016", "Continuity", "Are DR procedures tested annually?", "Art.21(2)(c)", 1.5, True]
    ],
    "recommendations": {
        "RMM001": "Submit registration details to the NCSC portal immediately.",
        "RMM002": "Formalize board oversight. Schedule quarterly cybersecurity reviews in board minutes.",
        "RMM006": "Implement automated patch management to ensure critical patches are applied < 30 days.",
        "RMM009": "Deploy Multi-Factor Authentication (MFA) on ALL remote and admin accounts immediately.",
        "RMM012": "Audit top 5 critical vendors. Update contracts to include 'Right to Audit' clauses.",
        "RMM015": "Update Incident Response Plan to include the specific 24h 'Early Warning' template.",
        "RMM016": "Conduct a full disaster recovery test with a disconnection from the main network."
    }
}

# Control-specific remediation playbook
# Each RMM has a specific, actionable remediation entry instead of a
# generic "Review Article 21" line. Every entry names an accountable
# owner, a remediation window (30/60/90 days, used to build the
# roadmap), the controls it depends on, the evidence required to close
# it, and a target maturity score so management can track progress.
DEFAULT_REMEDIATION = {
    "RMM001": {
        "action": "Submit organization registration to the national CSIRT/NCSC portal and record the confirmation reference.",
        "owner": "Compliance Officer / DPO",
        "timeline": "30 days",
        "dependencies": "Confirmed entity classification (essential vs important)",
        "evidence": "NCSC registration confirmation ID",
        "target": 100,
    },
    "RMM002": {
        "action": "Formalize board oversight: minute quarterly cyber reviews, approve an 18-month security budget, and complete mandatory board cyber training.",
        "owner": "Board / Executive Sponsor",
        "timeline": "60 days",
        "dependencies": "Board meeting calendar; annual budget cycle",
        "evidence": "Board minutes, approved budget line, training completion records",
        "target": 90,
    },
    "RMM003": {
        "action": "Approve and publish an ISMS security policy set covering all NIS2 Art.21(2) risk areas; assign policy owners and annual review dates.",
        "owner": "CISO",
        "timeline": "60 days",
        "dependencies": "Risk assessment (RMM004)",
        "evidence": "Signed, version-controlled ISMS policy set",
        "target": 90,
    },
    "RMM004": {
        "action": "Run a documented annual risk assessment and formally identify and classify critical clinical assets (EHR, PACS, LIS).",
        "owner": "CISO / Risk Manager",
        "timeline": "60 days",
        "dependencies": "Asset inventory (RMM007)",
        "evidence": "Risk register and critical-asset register",
        "target": 90,
    },
    "RMM005": {
        "action": "Establish annual control testing/internal audit and a documented process to update measures after every incident.",
        "owner": "Internal Audit / CISO",
        "timeline": "90 days",
        "dependencies": "ISMS policy (RMM003)",
        "evidence": "Audit reports and post-incident review records",
        "target": 85,
    },
    "RMM006": {
        # Reviewer: use risk-based SLAs, not a flat 30-day rule.
        "action": ("Adopt risk-based patch SLAs: critical internet-facing vulnerabilities treated within "
                   "48-72h, high within 14 days, others within 30 days, with exceptions documented and "
                   "formally approved. Test backup restorability annually and make cyber-hygiene training mandatory."),
        "owner": "IT Operations Lead",
        "timeline": "30 days",
        "dependencies": "Vulnerability scanning, patch automation, backup platform",
        "evidence": "Risk-based patch SLA policy, exception register, backup restore-test logs, training records",
        "target": 90,
    },
    "RMM007": {
        "action": "Maintain an automated, up-to-date asset inventory with ownership and criticality tags.",
        "owner": "IT Operations Lead",
        "timeline": "60 days",
        "dependencies": "CMDB / network discovery tooling",
        "evidence": "Asset inventory export with last-updated timestamps",
        "target": 90,
    },
    "RMM008": {
        "action": "Enforce background checks for sensitive roles and immediate access revocation on exit via a joiner-mover-leaver process.",
        "owner": "HR / IT Security",
        "timeline": "60 days",
        "dependencies": "HR system to IAM integration",
        "evidence": "Screening records and leaver deprovisioning logs",
        "target": 90,
    },
    "RMM009": {
        "action": "Enforce MFA on ALL remote and administrative access and apply least-privilege RBAC across systems.",
        "owner": "IT Security / IAM Lead",
        "timeline": "30 days",
        "dependencies": "Identity provider (e.g., Okta) rollout",
        "evidence": "MFA coverage report and privileged-access review",
        "target": 100,
    },
    "RMM010": {
        "action": "Secure server and communications rooms with logged access control and environmental monitoring.",
        "owner": "Facilities / IT",
        "timeline": "90 days",
        "dependencies": "Badge access system",
        "evidence": "Physical access logs and security audit",
        "target": 85,
    },
    "RMM011": {
        "action": "Encrypt patient data at rest and enforce TLS in transit; manage keys through a central key-management service.",
        "owner": "CISO / IT Security",
        "timeline": "60 days",
        "dependencies": "Key management service",
        "evidence": "Encryption configuration evidence and TLS scan results",
        "target": 90,
    },
    "RMM012": {
        "action": "Risk-assess critical vendors and embed security SLAs and right-to-audit clauses in supplier contracts.",
        "owner": "Procurement / CISO",
        "timeline": "90 days",
        "dependencies": "Vendor list and legal review",
        "evidence": "Vendor risk assessments and updated contracts",
        "target": 85,
    },
    "RMM013": {
        "action": "Build security requirements into system acquisition and run vulnerability management across new systems.",
        "owner": "IT Architecture / CISO",
        "timeline": "90 days",
        "dependencies": "Procurement process (RMM012)",
        "evidence": "Secure acquisition checklist and vulnerability scan reports",
        "target": 85,
    },
    "RMM014": {
        "action": "Finalize and approve the Incident Response Plan and run a tabletop exercise within 12 months.",
        "owner": "CISO / SOC Lead",
        "timeline": "60 days",
        "dependencies": "Detection capability (RMM015)",
        "evidence": "Approved IRP and tabletop exercise report",
        "target": 90,
    },
    "RMM015": {
        # Reviewer: 24h early warning needs operational proof.
        "action": ("Operationalize 24h early-warning reporting: name a reporting owner, define the escalation "
                   "path and weekend/out-of-hours cover, maintain a reporting template, and validate it with a "
                   "test submission. Sustain IDS/SIEM detection coverage."),
        "owner": "SOC Lead / Compliance Officer",
        "timeline": "30 days",
        "dependencies": "SIEM, on-call rota, CSIRT contact details",
        "evidence": "Named owner + escalation runbook, reporting template, test-submission record",
        "target": 100,
    },
    "RMM016": {
        # Reviewer: BCP/DR must state RTO/RPO for named clinical systems.
        "action": ("Define a BCP with documented RTO/RPO for each critical system like EHR, PACS, LIS, medication "
                   "systems, and network services. Test disaster recovery annually."),
        "owner": "IT Operations / Business Continuity Manager",
        "timeline": "90 days",
        "dependencies": "Critical-asset register (RMM004), DR environment",
        "evidence": "BCP with per-system RTO/RPO table and annual DR test report",
        "target": 90,
    },
}

# Default target maturity for an essential/important medium healthcare
# entity under NIS2: Tier 3 "Defined (Compliant)" = 75%.
DEFAULT_TARGET_MATURITY = 75.0

# Recovery objectives for the hospital's critical systems (RMM016 / BCP-DR).
# Rendered as an auditable RTO/RPO table in the report.
CRITICAL_SYSTEMS_RECOVERY = [
    # (system, criticality, RTO, RPO, key dependency)
    ("Electronic Health Record (EHR)", "Tier 1 - Critical", "4 hours", "15 minutes", "Core network, identity"),
    ("Medication management (ePMA / eMAR)", "Tier 1 - Critical", "2 hours", "15 minutes", "EHR, core network"),
    ("Laboratory Information System (LIS)", "Tier 1 - Critical", "4 hours", "30 minutes", "EHR, core network"),
    ("Picture Archiving & Communication (PACS)", "Tier 2 - High", "8 hours", "1 hour", "Storage, core network"),
    ("Core network & identity (AD / DNS / DHCP)", "Tier 1 - Critical", "1 hour", "15 minutes", "Power, data center"),
]

# Disaster-recovery test cadence (validates the RTO/RPO targets above).
DR_TESTING_PLAN = [
    ("Quarterly", "Backup restore test of one Tier 1 system (rotating schedule)", "Infrastructure Lead"),
    ("Semi-annually", "Incident & DR tabletop exercise (clinical + IT participants)", "CISO / SOC Lead"),
    ("Annually", "Full DR failover test with main-network isolation", "IT Operations / BC Manager"),
]

# Operational proof that a 24-hour 'early warning' can be submitted (Art. 23).
INCIDENT_REPORTING_READINESS = [
    ("Reporting owner", "SOC Lead (primary); Duty IT Manager (deputy)"),
    ("Escalation route", "SOC analyst -> SOC Lead -> CISO -> Executive on-call -> national CSIRT / NCSC"),
    ("Out-of-hours cover", "24/7 on-call rota (ref OPS-ROTA-2026), 15-minute acknowledgement SLA"),
    ("Reporting template", "NCSC early-warning template TMPL-EW-01 (held in IRP-PROC-007 v1.0)"),
    ("Statutory timeline", "Early warning within 24h, incident notification within 72h, final report within 1 month"),
    ("Test evidence", "Simulated early-warning submission TEST-EW-2026-01, completed 2026-03-08"),
]

# Core classes
class Question:
    """A single scored assessment question tied to one RMM domain.
    Holds both the static question definition (from the schema: id, domain,
    article reference, weight) and the mutable answer captured during an
    assessment (response/evidence/assurance), so one object represents the
    question throughout its lifecycle: defined -> asked -> answered -> scored.
    """
    def __init__(self, qid:int, rmm:str, section:str, text:str, article_ref:str, weight:float=1.0, evidence_required:bool=True):
        self.qid = qid
        self.rmm = rmm
        self.section = section
        self.text = text
        self.article_ref = article_ref
        self.weight = float(weight)
        self.evidence_required = bool(evidence_required)
        self.response: Optional[str] = None  # 'Yes'/'Partial'/'No'
        self.evidence: Optional[str] = None
        self.assurance: Optional[str] = None  # 'None'/'Low'/'Medium'/'High'

    def score(self, scoring_map:Dict[str,float]) -> float:
        """Raw points for the current response (Yes/Partial/No), scaled by
        this question's weight. Does NOT include the assurance factor.
        Callers apply that separately so it can be combined at either the
        question, RMM, or overall level."""
        base = scoring_map.get(self.response, 0.0)
        return base * self.weight

    def max_score(self, scoring_map:Dict[str,float]) -> float:
        """Points this question would contribute if answered 'Yes' i.e.
        its share of the denominator used to compute a percentage."""
        return scoring_map.get('Yes', 4.0) * self.weight

class RMM:
    """One Risk Management Measure domain (e.g. 'Access Control') and the
    subset of assessment questions that test it. Aggregating scores at this
    level is what lets the report show per-domain bars/radar points and
    flag specific weak domains, rather than only a single overall number.
    """
    def __init__(self, rmm_id:str, name:str, category:str, desc:str):
        self.rmm_id = rmm_id
        self.name = name
        self.category = category
        self.desc = desc
        self.questions: List[Question] = []

    def add_question(self, q:Question):
        self.questions.append(q)

    def calculate_score(self, scoring_map:Dict[str,float], assurance_weights:Dict[str,float]) -> float:
        """Weighted, assurance-adjusted implementation score for this domain,
        as a percentage (0-100).
        For each question: raw score (Yes/Partial/No * weight) is multiplied
        by the assurance factor for how well that answer is evidenced, so an
        unproven claim of "Yes" scores lower than a fully-documented one. The
        percentage is (sum of adjusted points) / (sum of best-case points at
        full/High assurance) i.e. "how close is this domain to a fully
        implemented, fully evidenced state".
        """
        if not self.questions:
            return 0.0
        total = 0.0
        max_total = 0.0
        for q in self.questions:
            q_base = q.score(scoring_map)
            # incorporate assurance: multiply by assurance weight (default 1.0 if missing)
            assurance_factor = assurance_weights.get(q.assurance or 'High', 1.0)
            total += q_base * assurance_factor
            max_total += q.max_score(scoring_map) * assurance_weights.get('High', 1.0)
        return (total / max_total) * 100.0 if max_total > 0 else 0.0


# Assessment engine
class Assessment:
    """Top-level orchestrator for one organization's NIS2 assessment.

    Owns the question/RMM data model (built from a schema), the captured
    answers (via run_interactive/run_demo/apply_answers), the scoring logic,
    and all report outputs (CSV, charts, PDF). A single Assessment instance
    represents one point-in-time assessment run for one organization.
    """
    def __init__(self, org_name:str="Healthcare Organization", schema:dict=None, scoring_map:dict=None,
                 tiers:dict=None, org_size:str="Medium", target_maturity:float=DEFAULT_TARGET_MATURITY):
        self.org_name = org_name
        self.org_size = org_size
        self.assessment_date = datetime.now()
        self.schema = schema or DEFAULT_SCHEMA
        self.scoring_map = scoring_map or DEFAULT_SCORING
        self.tiers = tiers or DEFAULT_MATURITY_TIERS
        self.target_maturity = float(target_maturity)
        self.rmms: Dict[str, RMM] = {}
        self.questions: List[Question] = []
        self.recommendations = self.schema.get('recommendations', {})
        # Structured, control-specific remediation (owner/timeline/dependencies/evidence/target).
        # Falls back to the rich default playbook if the schema does not supply one.
        self.remediation = self.schema.get('remediation', DEFAULT_REMEDIATION)
        # How the responses were captured. Set by run_demo()/run_interactive().
        self.data_source = "Not yet assessed"
        self._load_schema()

    def _load_schema(self):
        """Build the RMM and Question objects from self.schema (dict form,
        either DEFAULT_SCHEMA or one loaded from a JSON file via --schema).
        Runs once at construction time so the rest of the class can work
        with typed objects instead of raw dicts/tuples."""
        # create RMM objects
        for r in self.schema.get('rmm_definitions', []):
            self.rmms[r['id']] = RMM(r['id'], r['name'], r['category'], r.get('desc',''))
        # create questions
        for q in self.schema.get('questions', []):
            qid, rmm_id, section, text, article_ref, weight, evidence_required = q
            qobj = Question(qid, rmm_id, section, text, article_ref, weight, evidence_required)
            self.questions.append(qobj)
            if rmm_id in self.rmms:
                self.rmms[rmm_id].add_question(qobj)
            else:
                # create placeholder RMM if missing
                self.rmms[rmm_id] = RMM(rmm_id, rmm_id, 'Unknown', '')
                self.rmms[rmm_id].add_question(qobj)

    def run_interactive(self):
        """Ask the assessor each question on the terminal (Y/P/N), plus an
        optional evidence reference and an assurance rating, and store the
        answers directly on the Question objects. This is the "live
        interview" mode used for a genuine, evidence-based assessment,
        as opposed to run_demo() (synthetic) or apply_answers() (replayed
        from a saved dataset)."""
        self.data_source = "Interactive assessment (evidence-based responses)"
        print("\n" + "="*60)
        print(f"NIS2 ASSESSMENT: {self.org_name}")
        print("="*60)
        print("Answer each question: Y = Yes | P = Partial | N = No")
        print("For evidence, paste a short reference (policy name, doc id) or leave blank.")
        print("Assurance: choose None/Low/Medium/High (default High if left blank).")
        for q in self.questions:
            print(f"\n[Q{q.qid}] {q.rmm} | {q.article_ref}")
            print(q.text)
            if q.weight > 1.0:
                print("(WARNING!) CRITICAL QUESTION - High Impact on Score")
            # response
            while True:
                r = input("Response (Y/P/N): ").strip().upper()
                if r in ('Y','P','N'):
                    q.response = {'Y':'Yes','P':'Partial','N':'No'}[r]
                    break
                print("Enter Y, P or N.")
            # evidence
            if q.evidence_required:
                ev = input("Evidence ref (optional): ").strip()
                q.evidence = ev if ev else None
            # assurance
            a = input("Assurance (None/Low/Medium/High) [High]: ").strip().title()
            q.assurance = a if a in ASSURANCE_WEIGHTS else 'High'

    def run_demo(self, profile:str='tier2'):
        """Populate answers from a hard-coded synthetic profile instead of
        real evidence, purely so the tool can be demonstrated or smoke-
        tested end-to-end (CLI --demo flag) without an interactive session.
        data_source is tagged accordingly so the generated report cannot be
        mistaken for a genuine assessment."""
        self.data_source = f"Synthetic demo profile ('{profile}'). This is not real assessment evidence"
        # Simple synthetic profiles: 'low','medium','high'
        mapping = {
            'low': ['N']*30,
            'medium': ['P']*30,
            'high': ['Y']*30,
            'tier2': ['Y']*4 + ['P']*6 + ['N','Y','P','Y','Y','Y','N','P','Y','Y','P','N','N','P'] + ['P','N','N','P','P','N']
        }
        responses = mapping.get(profile, mapping['tier2'])
        for q, r in zip(self.questions, responses):
            q.response = {'Y':'Yes','P':'Partial','N':'No'}[r]

        # default assurance: High for Yes, Medium for Partial, Low for No
        for q in self.questions:
            if q.response == 'Yes':
                q.assurance = 'High'
            elif q.response == 'Partial':
                q.assurance = 'Medium'
            else:
                q.assurance = 'Low'

    def apply_answers(self, answers, source=None):
        """Apply a list of {qid, response, evidence, assurance} records captured
        during a real assessment, so the report is reproducible from a dataset."""
        by_id = {q.qid: q for q in self.questions}
        for a in answers:
            q = by_id.get(a.get('qid'))
            if not q:
                continue
            q.response = a.get('response')
            q.evidence = a.get('evidence')
            q.assurance = a.get('assurance') or 'High'
        self.data_source = source or "On-site assessment. Evidence-referenced responses"

    def calculate_overall(self) -> Tuple[float, str]:
        """Headline result for the whole assessment: the assurance-adjusted,
        weighted percentage across every question (not just per-RMM
        averages, so a domain with more/heavier questions has proportionate
        influence), plus the maturity tier that percentage falls into."""
        # compute weighted totals across all questions and RMMs
        total_points = 0.0
        max_points = 0.0
        for q in self.questions:
            # incorporate assurance at question level
            assurance_factor = ASSURANCE_WEIGHTS.get(q.assurance or 'High', 1.0)
            total_points += q.score(self.scoring_map) * assurance_factor
            max_points += q.max_score(self.scoring_map) * ASSURANCE_WEIGHTS.get('High', 1.0)
        percent = (total_points / max_points) * 100.0 if max_points > 0 else 0.0
        tier = self._determine_tier(percent)
        return percent, tier

    def _determine_tier(self, percent:float) -> str:
        """Look up which maturity tier (self.tiers) a percentage falls into."""
        for tname, info in self.tiers.items():
            low, high = info['range']
            if low <= percent <= high:
                return tname
        # fallback
        return 'Tier 1'

    def rmm_scores(self) -> Dict[str, float]:
        """Per-domain implementation percentages, keyed by RMM id. This is
        the data driving the bar chart, the radar chart, and the gap/
        remediation analysis below."""
        return {rmm_id: rmm.calculate_score(self.scoring_map, ASSURANCE_WEIGHTS) for rmm_id, rmm in self.rmms.items()}

    def critical_gaps(self, threshold:float=60.0) -> List[Tuple[str,float]]:
        """RMM domains scoring below 'threshold', weakest first. The input
        list for the report's priority remediation plan and 30/60/90-day
        roadmap. Called with self.target_maturity so "gap" means "below the
        organization's compliance target", not an arbitrary fixed cutoff."""
        scores = self.rmm_scores()
        gaps = [(rmm_id, score) for rmm_id, score in scores.items() if score < threshold]
        return sorted(gaps, key=lambda x: x[1])

    def consistency_checks(self) -> List[str]:
        """Sanity checks that flag internally-inconsistent answer patterns
        an auditor should query, rather than scoring failures. E.g. claiming
        strong incident-response maturity while detection/reporting (which
        IR depends on) is weak, or leaving admin/remote MFA disabled despite
        MFA being a heavily-weighted critical control."""
        msgs = []
        # map simple proxies: detection = RMM015 or RMM014. Hence, check RMM014 vs RMM015
        r = self.rmm_scores()
        if 'RMM014' in r and 'RMM015' in r:
            if r['RMM014'] > r['RMM015'] + 20:
                msgs.append("Incident Response maturity appears higher than detection/reporting capability; verify detection controls and evidence.")
        # MFA dependency: if MFA question is No but Access Control high, flag
        # find question 17 (MFA) by id
        q17 = next((q for q in self.questions if q.qid == 17), None)
        if q17 and q17.response == 'No':
            msgs.append("MFA is not enforced for admin/remote access (Q17). This is a critical control; consider immediate remediation.")
        return msgs

    
    # Interpretation helpers (added for reviewer feedback)  
    def scores_are_uniform(self, tolerance:float=0.5) -> bool:
        """True if every RMM resolves to (near) the same score. This is a
        sign of a default/uniform partial profile rather than real evidence."""
        vals = list(self.rmm_scores().values())
        if len(vals) < 2:
            return False
        return (max(vals) - min(vals)) <= tolerance

    def get_remediation(self, rmm_id:str) -> dict:
        """Return a structured remediation entry for an RMM, normalizing the
        legacy string-only format so the report code can rely on the fields."""
        entry = self.remediation.get(rmm_id)
        if isinstance(entry, dict):
            return entry
        action = entry if isinstance(entry, str) else self.recommendations.get(
            rmm_id, "Review the relevant Article 21 control, assign an owner, and document evidence.")
        return {"action": action, "owner": "TBD", "timeline": "60 days",
                "dependencies": "TBD", "evidence": "TBD", "target": int(self.target_maturity)}

    @staticmethod
    def _timeline_days(timeline:str) -> int:
        """Extract the leading integer from a timeline string (e.g. '30 days' -> 30)."""
        digits = ''.join(ch for ch in str(timeline) if ch.isdigit())
        return int(digits) if digits else 60

    def remediation_roadmap(self, threshold:float=75.0) -> Dict[str, List[Tuple[str, float, dict]]]:
        """Group sub-target RMMs into 30/60/90-day buckets for management tracking."""
        buckets: Dict[str, List[Tuple[str, float, dict]]] = {"30 days": [], "60 days": [], "90 days": []}
        for rmm_id, score in sorted(self.rmm_scores().items(), key=lambda x: x[1]):
            if score >= threshold:
                continue
            rem = self.get_remediation(rmm_id)
            days = self._timeline_days(rem.get("timeline", "60 days"))
            key = "30 days" if days <= 30 else "60 days" if days <= 60 else "90 days"
            buckets[key].append((rmm_id, score, rem))
        return buckets

    def score_components(self) -> Tuple[float, float, float]:
        """Return (assurance-adjusted weighted points, maximum points, percent)
        so the report can show how the headline percentage was derived."""
        total_points = 0.0
        max_points = 0.0
        for q in self.questions:
            af = ASSURANCE_WEIGHTS.get(q.assurance or 'High', 1.0)
            total_points += q.score(self.scoring_map) * af
            max_points += q.max_score(self.scoring_map) * ASSURANCE_WEIGHTS.get('High', 1.0)
        pct = (total_points / max_points * 100.0) if max_points > 0 else 0.0
        return total_points, max_points, pct

    def executive_risk_statement(self) -> str:
        """Plain-language risk statement for hospital leadership linking
        non-compliance to patient safety, service continuity and legal exposure."""
        percent, tier = self.calculate_overall()
        tier_label = self.tiers.get(tier, {}).get('label', '')
        gaps = self.critical_gaps(self.target_maturity)
        worst = [self.rmms[g[0]].name for g in gaps[:3]] if gaps else []
        worst_txt = ("The weakest areas are " + ", ".join(worst) + ". ") if worst else ""
        if percent < 50:
            posture = ("The organization is currently non-compliant with NIS2. Critical safeguards for "
                       "clinical systems are missing or unproven.")
        elif percent < 75:
            posture = ("The organization has foundational controls in place but is not yet compliant with "
                       "NIS2; several material gaps remain.")
        else:
            posture = ("The organization substantially meets NIS2 expectations, with residual gaps to close "
                       "and sustain.")
        return (
            f"As of {self.assessment_date.strftime('%Y-%m-%d')}, {self.org_name} scores {percent:.1f}% "
            f"({tier} - {tier_label}) against NIS2 risk-management requirements. {posture} {worst_txt}"
            "Unremediated gaps directly threaten patient safety (loss of access to EHR, imaging and "
            "medication systems), the continuity of clinical services (ransomware or outage with no tested "
            "recovery), and expose the organization to legal and regulatory liability under NIS2. This includes "
            "management accountability and potential penalties. Leadership should treat the items below as a "
            "time-bound program: address the 30-day actions immediately, fund the 60- and 90-day actions in "
            "this budget cycle, and review progress against the target maturity at the next board meeting."
        )

    
    # Outputs: CSV, charts, PDF
    def export_csv(self, filename:Optional[str]=None) -> str:
        """Dump every question's raw answer, evidence reference and computed
        score to CSV. This is the auditable raw-data artifact behind the
        PDF report. The PDF's numbers should always be reproducible from
        this file."""
        if not filename:
            filename = f"{self.org_name.replace(' ','_')}_assessment_{self.assessment_date.strftime('%Y%m%d')}.csv"
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Organization', self.org_name])
            w.writerow(['Assessment Date', self.assessment_date.isoformat()])
            w.writerow([])
            w.writerow(['Question ID','RMM','Article','Question Text','Weight','Response','Assurance','Evidence','Score'])
            for q in self.questions:
                w.writerow([q.qid, q.rmm, q.article_ref, q.text, q.weight, q.response or '', q.assurance or '', q.evidence or '', f"{q.score(self.scoring_map):.2f}"])
        return filename

    def generate_bar_chart(self, filename:Optional[str]=None) -> str:
        """Per-RMM implementation bar chart, color-coded red/amber/green
        against fixed thresholds, with reference lines for the Tier 2
        floor (50%) and the organization's target maturity. Lets a reader
        see at a glance which domains are below target without reading the
        underlying percentages."""
        if not filename:
            filename = f"{self.org_name.replace(' ','_')}_rmm_bar.png"
        scores = self.rmm_scores()
        ids = sorted(scores.keys())
        vals = [scores[i] for i in ids]
        colors_list = ['#d32f2f' if v < 50 else '#ffa726' if v < 75 else '#66bb6a' for v in vals]
        fig, ax = plt.subplots(figsize=(12,6))
        bars = ax.bar(ids, vals, color=colors_list, edgecolor='black')
        ax.axhline(50, color='orange', linestyle='--', linewidth=1,
                   label='Tier 2 threshold (50% - Managed)')
        ax.axhline(self.target_maturity, color='green', linestyle='--', linewidth=1,
                   label=f'Target maturity ({self.target_maturity:.0f}% - Tier 3 Defined/Compliant)')
        ax.set_ylim(0,100)
        ax.set_ylabel('Implementation (%)')
        ax.set_title(f'RMM Implementation Scores: {self.org_name}', pad=28)
        ax.legend(loc='lower center', bbox_to_anchor=(0.5, 1.0), ncol=2, fontsize=8, frameon=True)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x()+bar.get_width()/2, v+1, f"{v:.0f}%", ha='center', fontsize=9)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig(filename, dpi=300)
        plt.close()
        return filename

    def generate_radar_chart(self, filename:Optional[str]=None) -> str:
        """Category-level (Governance/Policy/Technical/Incident/Continuity)
        maturity radar, overlaid with the target-maturity ring, so the
        shape of the current profile relative to the target is visible in
        one image (a well-rounded polygon vs. a lopsided one)."""
        if not filename:
            filename = f"{self.org_name.replace(' ','_')}_radar.png"
        # group by category averages
        categories = {}
        for r in self.rmms.values():
            categories.setdefault(r.category, []).append(r.calculate_score(self.scoring_map, ASSURANCE_WEIGHTS))
        labels = list(categories.keys())
        values = [sum(vs)/len(vs) if vs else 0.0 for vs in categories.values()]
        values += values[:1]
        angles = np.linspace(0, 2*np.pi, len(labels), endpoint=False).tolist()
        angles += angles[:1]
        fig, ax = plt.subplots(figsize=(6,6), subplot_kw=dict(polar=True))
        # Current maturity profile
        ax.plot(angles, values, color='#1a237e', linewidth=2,
                label='Current maturity')
        ax.fill(angles, values, color='#1a237e', alpha=0.25)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels, size=10)
        ax.set_ylim(0,100)
        # Target maturity profile (labeled, per reviewer feedback)
        tgt = self.target_maturity
        ax.plot(angles, [tgt]*len(angles), color='green', linestyle='--', linewidth=1.5,
                label=f'Target maturity ({tgt:.0f}% - Tier 3 "Defined/Compliant")')
        plt.title(f"Maturity Profile: {self.org_name}", y=1.10)
        ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.08), fontsize=8, frameon=True)
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        return filename

    def generate_pdf(self, filename:Optional[str]=None) -> str:
        """Build the full PDF report using ReportLab's flowable/Platypus API:
        a list of 'elements' (Paragraphs, Tables, Images, Spacers) is
        assembled in order and laid out onto pages by 'doc.build()' at the
        end. The report is structured to answer, in order, the questions a
        hospital board or auditor would ask. Such as, what's the score and how was
        it derived, what's the business risk, what needs fixing and by whom/when, 
        can the hospital recover from an outage. Can it meet the legal 24h reporting
        duty, and finally the full evidence trail so every score is traceable to a specific answer.
        """
        if not filename:
            filename = f"{self.org_name.replace(' ','_')}_report_{self.assessment_date.strftime('%Y%m%d')}.pdf"
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        # Title / cover info
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, alignment=1, textColor=colors.HexColor('#1a237e'))
        elements.append(Paragraph("NIS2 Compliance Assessment Report", title_style))
        elements.append(Spacer(1,0.15*inch))
        elements.append(Paragraph(f"Organization: {self.org_name} ({self.org_size})", styles['Heading3']))
        elements.append(Paragraph(f"Date: {self.assessment_date.strftime('%Y-%m-%d')}", styles['Normal']))
        elements.append(Paragraph(f"Data source: {self.data_source}", styles['Normal']))
        elements.append(Spacer(1,0.1*inch))

        # Reusable small-text styles for dense tables / notes
        cell_style = ParagraphStyle('cell', parent=styles['Normal'], fontSize=7.5, leading=9)
        note_style = ParagraphStyle('note', parent=styles['Normal'], fontSize=8.5, leading=11,
                                    textColor=colors.HexColor('#5d4037'))
        cap_style = ParagraphStyle('cap', parent=styles['Normal'], fontSize=8, leading=10,
                                   textColor=colors.HexColor('#37474f'))

        # Summary
        percent, tier = self.calculate_overall()
        tier_label = self.tiers.get(tier, {}).get('label','')
        summary = [
            ['Overall Score', f"{percent:.1f}%"],
            ['Maturity Tier', f"{tier} - {tier_label}"],
            ['Target Maturity', f"{self.target_maturity:.0f}% (Tier 3 - Defined/Compliant)"]
        ]
        t = Table(summary, colWidths=[2.5*inch, 3.5*inch])
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(0,-1),colors.HexColor('#e8eaf6')),('GRID',(0,0),(-1,-1),1,colors.grey),('PADDING',(0,0),(-1,-1),8)]))
        elements.append(t)
        elements.append(Spacer(1,0.12*inch))

        # Scoring methodology (reviewer feedback: explain the headline score)
        total_pts, max_pts, _sp = self.score_components()
        method_txt = (
            f"<b>How to read this score.</b> Each question is answered Yes (4 pts), Partial "
            f"({self.scoring_map.get('Partial',1.0):.0f} pt) or No (0 pts) and multiplied by a weight "
            f"(critical controls such as MFA and 24h reporting carry higher weight, so RMM scores are "
            f"<i>not</i> weighted equally). Each answer is further scaled by an evidence-assurance factor "
            f"(None 0.0 / Low 0.5 / Medium 0.8 / High 1.0), so claims without evidence score lower. "
            f"The overall percentage is the weighted, assurance-adjusted total divided by the maximum "
            f"achievable. Maturity tiers: Tier 1 Initial 0-49%, Tier 2 Managed 50-74%, Tier 3 "
            f"Defined/Compliant 75-89%, Tier 4 Optimized 90-100%. The target for a {self.org_size.lower()} "
            f"healthcare entity is Tier 3 ({self.target_maturity:.0f}%). For this assessment the "
            f"assurance-adjusted weighted score is {total_pts:.1f} of a possible {max_pts:.1f} points "
            f"= {percent:.1f}%, placing the organization in {tier}."
        )
        elements.append(Paragraph(method_txt, note_style))
        elements.append(Spacer(1,0.12*inch))

        # Executive risk statement (reviewer feedback: leadership framing)
        elements.append(Paragraph("Executive Risk Statement", styles['Heading2']))
        elements.append(Paragraph(self.executive_risk_statement(), styles['Normal']))
        elements.append(Spacer(1,0.18*inch))

        # Charts (create temp files)
        bar = self.generate_bar_chart(tempfile.mktemp(suffix='.png'))
        radar = self.generate_radar_chart(tempfile.mktemp(suffix='.png'))
        elements.append(Image(bar, width=6*inch, height=3*inch))
        elements.append(Spacer(1,0.1*inch))
        elements.append(Image(radar, width=4*inch, height=4*inch))
        # Radar caption explaining the target profile (reviewer feedback)
        elements.append(Paragraph(
            f"The solid blue area is the current maturity by domain; the green dashed line is the target "
            f"profile ({self.target_maturity:.0f}%, Tier 3 'Defined/Compliant'). A regional hospital "
            f"delivers essential healthcare services and is treated as an 'essential entity' under NIS2 "
            f"(Annex I), so it is expected to reach the Defined/Compliant tier with controls fully documented, "
            f"implemented and routinely tested, rather than merely Managed. Tier 4 (Optimized) is not "
            f"required for compliance. Gaps between the blue area and the green line are the work still "
            f"required in each domain.",
            cap_style))
        elements.append(Spacer(1,0.15*inch))

        # Uniform-score caveat (reviewer feedback: explain identical bars)
        if self.scores_are_uniform():
            uniform_val = next(iter(self.rmm_scores().values()), 0.0)
            elements.append(Paragraph(
                f"<b>Note on identical scores:</b> every domain resolves to ~{uniform_val:.0f}%. This reflects "
                f"a uniform '{(self.questions[0].response if self.questions else 'Partial')}' response profile "
                f"across all questions rather than evidence of genuinely identical maturity per domain. Before "
                f"relying on these figures, confirm each answer against real evidence so that domain scores "
                f"differentiate.", note_style))
            elements.append(Spacer(1,0.15*inch))

        # Priority remediation plan: control-specific, with owner/due/evidence
        gaps = self.critical_gaps(self.target_maturity)
        if gaps:
            elements.append(Paragraph("Priority Remediation Plan", styles['Heading2']))
            elements.append(Paragraph(
                "Each gap below the target maturity has a control-specific action with an accountable owner, "
                "due window, dependencies and the evidence required to close it.", cap_style))
            elements.append(Spacer(1,0.06*inch))
            header_cell = ParagraphStyle('hcell', parent=cell_style, textColor=colors.white)
            data = [[Paragraph('<b>RMM</b>', header_cell), Paragraph('<b>Now</b>', header_cell),
                     Paragraph('<b>Target</b>', header_cell), Paragraph('<b>Priority</b>', header_cell),
                     Paragraph('<b>Control-specific remediation</b>', header_cell)]]
            for rmm_id, score in gaps:
                priority = 'Critical' if score < 40 else 'High' if score < 60 else 'Medium'
                rem = self.get_remediation(rmm_id)
                name = self.rmms[rmm_id].name if rmm_id in self.rmms else rmm_id
                detail = (
                    f"{rem['action']}<br/>"
                    f"<b>Owner:</b> {rem['owner']} &nbsp; <b>Due:</b> {rem['timeline']}<br/>"
                    f"<b>Depends on:</b> {rem['dependencies']}<br/>"
                    f"<b>Evidence:</b> {rem['evidence']}"
                )
                data.append([
                    Paragraph(f"<b>{rmm_id}</b><br/>{name}", cell_style),
                    Paragraph(f"{score:.0f}%", cell_style),
                    Paragraph(f"{rem['target']}%", cell_style),
                    Paragraph(priority, cell_style),
                    Paragraph(detail, cell_style),
                ])
            tbl = Table(data, colWidths=[0.95*inch, 0.5*inch, 0.5*inch, 0.65*inch, 3.9*inch], repeatRows=1)
            tbl.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#c62828')),
                                     ('GRID',(0,0),(-1,-1),0.5,colors.grey),
                                     ('VALIGN',(0,0),(-1,-1),'TOP'),
                                     ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white, colors.HexColor('#fbe9e7')])]))
            elements.append(tbl)
            elements.append(Spacer(1,0.2*inch))

        # 30-60-90 day remediation roadmap (reviewer feedback)
        roadmap = self.remediation_roadmap(self.target_maturity)
        if any(roadmap.values()):
            elements.append(Paragraph("30-60-90 Day Remediation Roadmap", styles['Heading2']))
            elements.append(Paragraph(
                "Sequenced view of the same actions so management can track progress towards target maturity "
                "after this assessment.", cap_style))
            elements.append(Spacer(1,0.06*inch))
            window_labels = {"30 days": "Days 0-30 (Immediate)",
                             "60 days": "Days 31-60 (Short term)",
                             "90 days": "Days 61-90 (Medium term)"}
            rdata = [['Window', 'RMM', 'Now', 'Target']]
            for window in ["30 days", "60 days", "90 days"]:
                items = roadmap[window]
                for i, (rid, score, rem) in enumerate(items):
                    name = self.rmms[rid].name if rid in self.rmms else rid
                    rdata.append([
                        window_labels[window] if i == 0 else '',
                        f"{rid} {name}",
                        f"{score:.0f}%",
                        f"{rem['target']}%",
                    ])
            rtbl = Table(rdata, colWidths=[1.7*inch, 2.8*inch, 1.0*inch, 1.0*inch], repeatRows=1)
            rtbl.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1a237e')),
                                      ('TEXTCOLOR',(0,0),(-1,0),colors.white),
                                      ('GRID',(0,0),(-1,-1),0.5,colors.grey),
                                      ('FONTSIZE',(0,0),(-1,-1),8),
                                      ('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
            elements.append(rtbl)
            elements.append(Spacer(1,0.2*inch))

        # Business continuity recovery objectives (reviewer feedback: RTO/RPO)
        hcw = ParagraphStyle('hcw', parent=cell_style, textColor=colors.white)
        elements.append(Paragraph("Business Continuity: Critical System Recovery Objectives", styles['Heading2']))
        elements.append(Paragraph(
            "Recovery Time Objective (RTO) and Recovery Point Objective (RPO) targets for the hospital's "
            "critical systems (basis for RMM016). These objectives are validated by the disaster-recovery "
            "test schedule below.", cap_style))
        elements.append(Spacer(1,0.06*inch))
        bcp = [[Paragraph('<b>Critical system</b>',hcw), Paragraph('<b>Criticality</b>',hcw),
                Paragraph('<b>RTO</b>',hcw), Paragraph('<b>RPO</b>',hcw), Paragraph('<b>Key dependency</b>',hcw)]]
        for s, crit, rto, rpo, dep in CRITICAL_SYSTEMS_RECOVERY:
            bcp.append([Paragraph(s,cell_style), Paragraph(crit,cell_style), Paragraph(rto,cell_style),
                        Paragraph(rpo,cell_style), Paragraph(dep,cell_style)])
        bt = Table(bcp, colWidths=[2.2*inch,1.2*inch,0.75*inch,0.85*inch,1.5*inch], repeatRows=1)
        bt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1a237e')),
                                ('GRID',(0,0),(-1,-1),0.5,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),
                                ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white, colors.HexColor('#e8eaf6')])]))
        elements.append(bt)
        elements.append(Spacer(1,0.1*inch))
        elements.append(Paragraph("Disaster-recovery test schedule", styles['Heading3']))
        dr = [[Paragraph('<b>Frequency</b>',hcw), Paragraph('<b>Test</b>',hcw), Paragraph('<b>Owner</b>',hcw)]]
        for fr, desc, own in DR_TESTING_PLAN:
            dr.append([Paragraph(fr,cell_style), Paragraph(desc,cell_style), Paragraph(own,cell_style)])
        drt = Table(dr, colWidths=[1.2*inch,3.5*inch,1.8*inch], repeatRows=1)
        drt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#37474f')),
                                 ('GRID',(0,0),(-1,-1),0.5,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP')]))
        elements.append(drt)
        elements.append(Spacer(1,0.2*inch))

        # Incident reporting / 24h early-warning readiness (reviewer feedback)
        elements.append(Paragraph("Incident Reporting & 24-Hour Early-Warning Readiness (Art. 23)", styles['Heading2']))
        elements.append(Paragraph(
            "Operational proof that the organization can submit a NIS2 'early warning' within 24 hours of "
            "becoming aware of a significant incident.", cap_style))
        elements.append(Spacer(1,0.06*inch))
        ir = [[Paragraph('<b>Element</b>',hcw), Paragraph('<b>Detail</b>',hcw)]]
        for k, v in INCIDENT_REPORTING_READINESS:
            ir.append([Paragraph(f"<b>{k}</b>",cell_style), Paragraph(v,cell_style)])
        irt = Table(ir, colWidths=[1.6*inch,4.9*inch], repeatRows=1)
        irt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1a237e')),
                                 ('GRID',(0,0),(-1,-1),0.5,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),
                                 ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white, colors.HexColor('#e8eaf6')])]))
        elements.append(irt)
        elements.append(Spacer(1,0.2*inch))

        # Consistency checks
        checks = self.consistency_checks()
        if checks:
            elements.append(Paragraph("Consistency Checks", styles['Heading2']))
            for c in checks:
                elements.append(Paragraph(f"• {c}", styles['Normal']))
            elements.append(Spacer(1,0.2*inch))

        # Appendix: detailed Qs
        elements.append(PageBreak())
        elements.append(Paragraph("Appendix: Detailed Findings", styles['Heading2']))
        appx = ParagraphStyle('appx', parent=styles['Normal'], fontSize=7, leading=8.5)
        appx_h = ParagraphStyle('appxh', parent=appx, textColor=colors.white)
        detail = [[Paragraph('<b>ID</b>',appx_h), Paragraph('<b>RMM</b>',appx_h), Paragraph('<b>Article</b>',appx_h),
                   Paragraph('<b>Question</b>',appx_h), Paragraph('<b>Resp.</b>',appx_h), Paragraph('<b>Assur.</b>',appx_h),
                   Paragraph('<b>Evidence (document reference)</b>',appx_h), Paragraph('<b>Pts</b>',appx_h)]]
        for q in self.questions:
            detail.append([Paragraph(str(q.qid),appx), Paragraph(q.rmm,appx), Paragraph(q.article_ref,appx),
                           Paragraph(q.text, appx), Paragraph(q.response or '',appx), Paragraph(q.assurance or '',appx),
                           Paragraph(q.evidence or '',appx), Paragraph(f"{q.score(self.scoring_map):.1f}",appx)])
        dtable = Table(detail, colWidths=[0.3*inch,0.6*inch,0.75*inch,1.7*inch,0.5*inch,0.55*inch,1.75*inch,0.35*inch], repeatRows=1)
        dtable.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1a237e')),
                                    ('GRID',(0,0),(-1,-1),0.5,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),
                                    ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white, colors.HexColor('#f5f5f5')])]))
        elements.append(dtable)

        doc.build(elements)

        # Clean-up temp images
        try:
            os.remove(bar)
            os.remove(radar)
        except Exception:
            pass

        return filename


# CLI and helpers
def load_schema_from_file(path:str) -> dict:
    """Load a custom question/RMM schema (--schema) or a saved answers
    dataset (--responses) from a JSON file. Both use plain JSON so an
    assessor can edit the questionnaire or hand off a captured dataset
    without touching Python code."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def run_sensitivity(assessment:Assessment, partial_values:List[float]) -> Dict[float,float]:
    """Recompute the overall percentage under different 'Partial' point
    values (e.g. 0.5 vs 1.0 vs 2.0) to show how sensitive the headline
    score is to that one subjective scoring choice, then restore the
    original value so the assessment object is left unchanged. Used for
    the --sensitivity CLI flag as a methodological transparency check,
    not as part of the scored result itself."""
    results = {}
    original_partial = assessment.scoring_map.get('Partial', DEFAULT_SCORING['Partial'])
    for pv in partial_values:
        assessment.scoring_map['Partial'] = pv
        percent, tier = assessment.calculate_overall()
        results[pv] = percent
    assessment.scoring_map['Partial'] = original_partial
    return results

def main_cli():
    """Command-line entry point: parses arguments, builds an Assessment,
    populates it with answers, prints a summary to the terminal, and writes out the CSV,
    charts and PDF report. Optionally runs the Partial-score sensitivity
    analysis at the end."""
    parser = argparse.ArgumentParser(description="NIS2 Healthcare Compliance Assessment Tool")
    parser.add_argument('--org', type=str, default="Regional Hospital", help="Organization name")
    parser.add_argument('--org-size', type=str, default="Medium", help="Organization size (Small/Medium/Large)")
    parser.add_argument('--target', type=float, default=DEFAULT_TARGET_MATURITY,
                        help="Target maturity percentage (default 75 = Tier 3 Defined/Compliant)")
    parser.add_argument('--schema', type=str, help="Path to JSON schema file (optional)")
    parser.add_argument('--demo', action='store_true', help="Run demo (non-interactive) using synthetic profile")
    parser.add_argument('--responses', type=str, help="Path to JSON assessment responses/evidence dataset")
    parser.add_argument('--sensitivity', action='store_true', help="Run sensitivity analysis on Partial score")
    parser.add_argument('--partial', type=float, help="Override Partial score value (float)")
    args = parser.parse_args()

    schema = DEFAULT_SCHEMA
    if args.schema:
        try:
            schema = load_schema_from_file(args.schema)
        except Exception as e:
            print(f"Failed to load schema file: {e}. Using default schema.")

    scoring = dict(DEFAULT_SCORING)
    if args.partial is not None:
        scoring['Partial'] = float(args.partial)

    assessment = Assessment(org_name=args.org, schema=schema, scoring_map=scoring,
                            org_size=args.org_size, target_maturity=args.target)

    if args.responses:
        data = load_schema_from_file(args.responses)
        if data.get('org'):
            assessment.org_name = data['org']
        if data.get('org_size'):
            assessment.org_size = data['org_size']
        if data.get('date'):
            try:
                assessment.assessment_date = datetime.strptime(data['date'], '%Y-%m-%d')
            except Exception:
                pass
        assessment.apply_answers(data.get('answers', []), data.get('data_source'))
    elif args.demo:
        assessment.run_demo('tier2')
    else:
        assessment.run_interactive()

    percent, tier = assessment.calculate_overall()
    print("\n" + "="*60)
    print(f"Overall compliance: {percent:.1f}%  |  Maturity Tier: {tier} - {assessment.tiers[tier]['label']}")
    print("="*60)
    # show RMM scores
    for rmm_id, score in sorted(assessment.rmm_scores().items()):
        status = "PASS" if score >= 75 else "WARN" if score >= 50 else "FAIL"
        print(f"{rmm_id:6s} {assessment.rmms[rmm_id].name:25s} {score:6.1f}%  {status}")

    # Consistency checks
    checks = assessment.consistency_checks()
    if checks:
        print("\nConsistency checks:")
        for c in checks:
            print(" -", c)

    # Outputs
    csvf = assessment.export_csv()
    print(f"\nCSV exported: {csvf}")
    bar = assessment.generate_bar_chart()
    radar = assessment.generate_radar_chart()
    print(f"Charts saved: {bar}, {radar}")
    pdf = assessment.generate_pdf()
    print(f"PDF report generated: {pdf}")

    if args.sensitivity:
        print("\nRunning sensitivity analysis on Partial score (0.5,1.0,2.0)...")
        res = run_sensitivity(assessment, [0.5, 1.0, 2.0])
        for pv, pct in res.items():
            print(f" Partial={pv:.2f} -> Overall {pct:.1f}%")

if __name__ == '__main__':
    main_cli()