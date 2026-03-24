# FEPD SoI Final Validation Report (Problem->MVP)

## 0. Front matter

### Abstract
The validated problem is that digital forensic investigations are often slow, fragmented across tools, and difficult to defend in court when integrity, reproducibility, and auditability are inconsistent. The primary end-user is the forensic analyst/investigator working in lab or incident response settings, with secondary stakeholders including legal teams, compliance officers, and security operations leads. FEPD provides a one-line solution: a unified, forensic-safe evidence processing and analysis platform with ingestion, timeline reconstruction, artifact exploration, ML-assisted triage, and chain-of-custody controls. In validated system runs, the platform processed 203 artifacts and 23,249 normalized events from a test case, with all 18/18 critical module imports passing and 14/14 audit verification tests passing. From prototype to MVP, the project moved from mocked and partially disconnected flows toward verified end-to-end operation in core paths, with explicit fixes for critical integrity and workflow issues. The next step is targeted hardening: close remaining high/medium audit findings (race conditions, model loading security, and full reproducibility controls) and execute expanded real-user pilots with longitudinal KPI tracking.

### Keywords / Index Terms
Digital forensics, chain of custody, evidence integrity, forensic timeline reconstruction, incident response analytics, UEBA, malware triage, forensic auditability

### Document control and metadata
| Field | Value |
|---|---|
| Version | v1.0 / final |
| Prepared by | FEPD Engineering and Forensic Architecture Team |
| Last updated | 2026-03-24 |
| Project outcome | GO (with hardening backlog) |
| Primary pain metric | End-to-end investigation cycle time with admissibility-grade integrity evidence |
| Stage reached | MVP |

---

## 1. Project snapshot

### Problem statement
Digital investigations are commonly slowed by tool fragmentation, manual handoffs, repeated data handling, and inconsistent evidentiary controls. Analysts often need to switch among separate tools for ingest, artifact extraction, timeline analysis, and reporting, which increases cognitive load and introduces opportunities for procedural error. This creates operational pain in incident response timelines and legal pain when evidence traceability, timestamp consistency, and reproducibility are challenged. The end-user impact is delayed decisions, reduced confidence in findings, and extra effort to prepare defensible reports. Institutions face higher investigation cost, slower response, and increased contestability of conclusions.

### One-line value proposition
For forensic analysts who lose time and confidence due to fragmented tooling and inconsistent evidentiary controls, our solution unifies ingestion, analysis, timeline, ML triage, and reporting with built-in integrity and chain-of-custody safeguards so they get faster case throughput and stronger court-defensible outputs.

### Stage summary table
| Stage | Key question answered | What was produced | Best evidence | Status |
|---|---|---|---|---|
| Problem and end-user | What pain is real? | Problem framing for forensic workflow fragmentation and defensibility risk | Executive and architecture docs, forensic/security audits | Done |
| Ideation | Which concept should we pursue? | Multi-feature architecture with terminal, artifacts, timeline, reporting, and ML layers | Feature and architecture documentation set | Done |
| PoC | Can the core concept work? | Core components and subsystem prototypes across ingest, VFS, terminal, analytics | Subsystem audit and implementation status docs | Done |
| Prototype | Can the solution work end-to-end? | Integrated application with real case ingestion and multi-tab UI workflow | Full system test report (artifact/event processing and operational tabs) | Done |
| MVP | Does it reduce the pain in real use? | Verified MVP with critical issue remediation and passing audit test suite | Audit-complete verification with 14/14 tests passed | Done |

---

## 2. Problem and end-user validation

### Who exactly is the end-user?
Primary end-user: digital forensic analyst / incident investigator using workstation-based forensic tooling in enterprise, institutional, or law-enforcement-like investigation environments.

Secondary stakeholders: case supervisors, legal counsel, compliance teams, SOC/IR leads, and QA/audit teams who rely on evidentiary quality and reproducibility.

Context of use: analysis of seized or acquired evidence (for example E01 images, logs, memory artifacts) in controlled lab settings with legal and policy constraints.

### Trigger situation, baseline, and constraints
| Item | What to capture |
|---|---|
| Trigger situation | Problem appears when investigators need to correlate multiple evidence sources rapidly while preserving defensible chain-of-custody and minimizing manual cross-tool work. |
| Baseline | Before stabilization, audits identified critical gaps (for example disconnected ML/inference paths, mock data risk in some enhanced flows, and integrity/process weaknesses). Baseline captured through formal audit reports and subsystem reviews. |
| Severity | High institutional impact: delayed response, potential evidence contestability, and analyst inefficiency in high-pressure investigations. |
| Constraints | Strict forensic integrity requirements, offline/controlled operation expectations, large evidence sizes, limited analyst time, legal scrutiny, and reproducibility expectations. |
| Success metric anchor | Reduced end-to-end investigation cycle time while maintaining verifiable evidence integrity and traceable audit logs. |

### Problem evidence table
| Evidence type | Sample size / source | Key insight | Implication for design | Evidence link or appendix ref |
|---|---|---|---|---|
| Full-system execution report | 1 integrated case run (adcdsc / LoneWolf.E01) | System processed 203 artifacts and 23,249 events with all critical tabs operational | Confirmed need to optimize integrated workflow rather than isolated components | docs/FULL_SYSTEM_TEST_REPORT.md |
| Security + forensic audit | Full codebase audit scope | Critical findings around model loading security and timestamp consistency require hardening for defensibility | Prioritize integrity and security controls as first-class design constraints | SECURITY_FORENSIC_AUDIT.md |
| Forensic audit and verification | Multi-phase audit plus verification tests | 3 critical findings fixed and verified; 14/14 tests passed after remediation | MVP gate can proceed with explicit residual backlog | docs/AUDIT_COMPLETE_VERIFICATION.md |
| Subsystem audit | Terminal, visualization, FEPD-OS modules (~11,700 LOC in scope) | Architecture strong but integration/import fragility identified | Introduce stricter integration contracts and compatibility checks | SUBSYSTEM_AUDIT_REPORT.md |

---

## 3. Prior work, literature, and existing solutions
Existing practice includes commercial and open-source forensic suites that provide ingestion, artifact review, and reporting, but teams still face challenges in workflow continuity, explainability of automated triage, and institutional adaptation. Internally, FEPD documentation and audit history show iterative advancement from component-heavy implementation toward integrated and validated behavior.

### Benchmark and gap table
| Existing solution / paper | What it does well | Limits or gap for our context | What we learned or adopted | Implication for our design |
|---|---|---|---|---|
| Autopsy-style workflow (documented comparison in project docs) | Strong ingest/report workflow and category-based analysis | Limited fit for custom integrated terminal plus tailored ML explainability requirements | Wizarded ingest, structured report flow, category navigation patterns | Keep familiar forensic UX while enabling deeper integrated intelligence |
| Magnet/Review-style analysis patterns (documented comparison in project docs) | Strong review UI and timeline exploration | Context-specific integration and reproducibility controls still need local implementation | Multi-pane artifacts, timeline exploration, filter-first workflow | Maintain analyst speed with defensible evidence controls |
| Prior internal prototype state (audit findings) | Broad capability surface and rapid feature growth | Disconnected/mocked paths and inconsistent contracts in places | Formal audits and targeted hardening loops improve reliability quickly | Enforce contract testing and integration validation before feature expansion |
| Internal institutional workarounds | Analysts can complete cases using manual toolchains | High context switching, slower cycle time, lower consistency | Build one orchestrated path from ingest to report | Reduce manual handoffs and improve repeatability |

---

## 4. Ideation and solution selection
Multiple pathways were explored through documented feature tracks and subsystem variants. The selected direction prioritized a unified platform with strict forensic controls and modular extensibility.

### Idea selection matrix
| Idea | Desirability evidence | Feasibility evidence | Viability / operational viability | Decision + rationale |
|---|---|---|---|---|
| Build-only visualization layer | Users value fast visual pattern detection | High feasibility in isolation | Limited if not tied to ingestion/integrity/reporting | Not selected as primary path (kept as subsystem) |
| Build-only terminal forensic shell | Strong analyst preference for command-style workflows | Feasible and implemented | Incomplete without full case lifecycle integration | Not selected as standalone (integrated into full platform) |
| Unified end-to-end forensic platform (selected) | Aligns to analyst pain: fewer handoffs, single context | Proven by integrated run and passing verification tests | Supports institutional adoption with auditable workflow | Selected: best balance of desirability, feasibility, and viability |

### MoSCoW prioritization
| Priority band | Features / capabilities included here | Why this priority is correct |
|---|---|---|
| Must | Evidence ingest, integrity verification, chain-of-custody, core artifacts/timeline/reporting, baseline terminal operations | Minimum required for defensible and usable forensic workflow |
| Should | ML anomaly triage, UEBA baseline commands, enhanced correlation outputs, robust test contracts | Strongly improves analyst productivity and signal triage |
| Could | Additional language/reporting polish, advanced heatmap and UX enhancements, deeper automation assistants | Valuable but not required to validate primary pain reduction |
| Won't (now) | Full-scale enterprise orchestration, every advanced parser edge case, all backlog hardening items in one cycle | Avoids over-scoping and protects MVP delivery quality |

---

## 5. Solution design and implementation

### System overview
FEPD implements a layered forensic workflow:
1. Case and evidence onboarding with integrity-first handling.
2. Evidence processing and normalization into artifacts/events.
3. Unified forensic store and section engines for tab hydration.
4. Analyst-facing views (artifacts, timeline, ML analytics, terminal, reporting).
5. Auditability controls (chain-of-custody logging, integrity checks, ML prediction binding).

Architecture/workflow sources are maintained in project architecture and implementation docs.

Insert architecture / workflow / build figure here.

### Key design decisions
| Decision | Alternatives considered | Why this choice was made | Evidence or constraint behind the choice |
|---|---|---|---|
| Prioritize chain-of-custody and integrity controls in core workflow | Add controls later as compliance add-on | Forensic admissibility requires integrity by design, not retrofit | Security and forensic audit findings highlighted legal risk of weak controls |
| Keep modular subsystems but integrate through unified contracts | Keep isolated feature modules with ad hoc glue | Reduced breakage and clearer ownership for end-to-end behavior | Subsystem and ML audits showed disconnected paths and inconsistent interfaces |
| Use staged hardening with audit-verification loops | Big-bang rewrite | Faster risk reduction with measurable gates | Audit-complete verification demonstrates critical fixes + pass evidence |

### REAL vs SIMULATED matrix
| Component / step | Real | Simulated / mocked / manual | Notes for future automation or improvement |
|---|---|---|---|
| End-user interaction | Yes | No | Real analyst-facing UI and command workflows are operational |
| Data capture / evidence ingest | Yes | Partial | Core image/case ingest is real; broaden additional format edge cases |
| Core logic / workflow | Yes | Partial | Core pipelines operational; some enhanced/legacy areas were historically mocked per audit and require continued cleanup |
| Integration / analytics | Yes | Partial | Integrated ML and analytics available; hardening continues for consistency and model-handling security |

---

## 6. Development journey across SoI stages

### Stage-wise learning table
| Stage | Goal or hypothesis | Build / activity completed | Observed result | Main learning | Gate decision |
|---|---|---|---|---|---|
| Problem and end-user | Analysts need less tool fragmentation and stronger defensibility | Problem framing and architecture definitions | Clear pain around cycle time and evidentiary confidence | Defensibility must be first-order requirement | Proceed |
| Ideation | Multiple architectures can satisfy needs | Feature-track exploration across UI, terminal, reporting, ML | Rich options but integration complexity emerged | Select unified platform and contracts | Proceed |
| PoC | Core modules can function | Subsystem-level implementation and audits | Modules capable, but integration/import risks present | Add integration governance and tests | Proceed with fixes |
| Prototype | End-to-end flow can run on real case | Full application run with evidence ingestion and tab loading | 203 artifacts and 23,249 events processed successfully | Throughput and integration viable | Proceed |
| MVP | Critical risks can be remediated with proof | Critical fix implementation and verification suite | 14/14 verification tests passed; all critical findings addressed in audited set | MVP can ship with explicit backlog | GO with hardening backlog |

---

## 7. Evaluation and outcomes

### Validation hypothesis and success criteria
We believe that forensic analysts will achieve faster and more defensible investigations if they use FEPD in real case workflows. We will measure this by investigation cycle-time proxy and evidentiary control completeness. We consider it successful if integrated runs complete with stable outputs, integrity controls verify correctly, and critical audit issues are closed with passing verification tests.

### KPI table: target vs actual
| Metric | Baseline | Target | Actual | How measured | N / sample | Status | Evidence ref |
|---|---|---|---|---|---|---|---|
| Primary pain metric: integrated cycle throughput with evidentiary controls | Fragmented workflows and critical control gaps in pre-fix audits | Demonstrate integrated end-to-end case run and verifiable control checks | Integrated run completed: 203 artifacts, 23,249 events; core system operational | Full system execution report plus audit verification | 1 full integrated case run + verification suite | Pass | docs/FULL_SYSTEM_TEST_REPORT.md; docs/AUDIT_COMPLETE_VERIFICATION.md |
| Critical quality gate pass rate | Critical findings open | All critical issues in scoped audit resolved and verified | 14/14 tests passed; critical fixes verified | Regression + critical fix test suites | 14 tests | Pass | docs/AUDIT_COMPLETE_VERIFICATION.md |
| Module readiness | Unknown/partial confidence | All required core imports pass | 18/18 modules imported successfully in test run | Backend import test execution | 18 modules | Pass | docs/FULL_SYSTEM_TEST_REPORT.md |
| Performance proxy: processing throughput | Not consistently tracked in single metric pre-fix | Process typical case without failure | 203 artifacts and 23,249 events processed in full run | End-to-end run telemetry from report | 1 integrated run | Pass | docs/FULL_SYSTEM_TEST_REPORT.md |

### User validation summary
| What worked well | What was confusing or failed | Suggested improvements | Representative quote or note |
|---|---|---|---|
| End-to-end case loading, tab hydration, and forensic terminal workflow operated as expected in full run | Some warnings from incomplete images and reserved partitions are operationally expected but may confuse new users | Improve warning categorization and UX messaging by severity/context | "All critical systems are functional and error-free" (full system report summary) |
| Chain-of-custody and integrity architecture is strong | Mixed timestamp handling and model-loading security required hardening attention | Complete remaining hardening backlog and enforce UTC/model verification policies globally | Security audit: "Conditional pass" pending critical/high remediation |
| Audit-driven stabilization improved confidence quickly | Legacy/disconnected or mocked paths in specific modules create risk if left unresolved | Continue dead-code cleanup and contract enforcement | ML/analytics and subsystem audit findings |

### Iteration log
| Version | Change made | Why it changed | Impact observed |
|---|---|---|---|
| Prototype | Broad feature implementation across ingest, tabs, terminal, ML, reporting | Establish feasibility and coverage | Capabilities present but with integration and assurance gaps |
| MVP v1 | Critical forensic/security fixes (hashing flow, ML binding, cleanup, verification) | Address highest admissibility and reliability risks | Verified critical fixes and passing test outcomes |
| MVP v2 / final | Consolidated verification and operational full-run confirmation | Confirm production readiness posture | GO outcome with explicit hardening backlog |

### Pain-point proof
| Original pain point | Best final evidence | Status |
|---|---|---|
| Investigation workflow is slow and fragmented, with defensibility risk | Unified run processed 203 artifacts/23,249 events; critical fixes verified with 14/14 tests; chain/integrity controls active | Validated (with remaining non-critical backlog) |

---

## 8. Responsible innovation, risks, and limitations

### Responsible practice and risk log
| Risk / concern | Why it matters | Mitigation / current control | Status or residual gap |
|---|---|---|---|
| Privacy / consent | Forensic data may include personal and sensitive content | Controlled case structure, audit logging, workflow controls | Partial: formalized consent/instrument packaging should be standardized in ops templates |
| Safety / physical risk | Primarily software/lab operation, low physical hazard | Safe lab/testbed usage and read-only evidence handling patterns | Low residual risk |
| Security / misuse | Compromised models or unsafe execution paths could invalidate trust | Security audit, critical remediation, verification suites, chain/integrity controls | Residual high/medium backlog remains (for example race conditions, model loading hardening completion) |
| Operational / adoption risk | Analysts may face warning fatigue or integration complexity | Progressive UX improvements, docs, workflow guidance | Partial: needs expanded user studies and training materials |

### Limitations and honest lessons
- Some audits documented historically disconnected or mocked flows in certain enhanced/legacy components; sustained cleanup remains necessary.
- MVP evidence is strong for integrated technical validation but limited in longitudinal field-user sample size.
- Not all high/medium audit findings were closed in the same cycle; backlog governance is essential.
- Reproducibility and benchmark consistency should be expanded from point-in-time reports to continuous KPI dashboards.

---

## 9. Handover, continuation, and next steps

### Current-state handover summary
| Current system / artefact state | What works reliably now | What is missing | Where the evidence / build instructions are kept |
|---|---|---|---|
| MVP integrated application state | Case loading, evidence processing, core tabs, terminal workflow, key integrity flows, critical fix verification | Full closure of remaining high/medium items; broader pilot validation | docs/FULL_SYSTEM_TEST_REPORT.md, docs/AUDIT_COMPLETE_VERIFICATION.md, SECURITY_FORENSIC_AUDIT.md, docs/COMPLETE_STATUS.md |

### Backlog for continuation or pivot
| Priority | Next task / experiment | Why this matters next | Owner / suggested role | Est. effort |
|---|---|---|---|---|
| High | Close remaining high security/integrity findings (model loading hardening, registry race conditions) | Protect legal defensibility and production trust | Security engineer + forensic architect | 3-5 days |
| High | Remove/replace residual mocked or disconnected analysis paths | Prevent false confidence and improve consistency | Core platform engineer | 4-6 days |
| Medium | Expand reproducibility/benchmark harness for recurring KPI capture | Move from one-off validation to sustained quality tracking | QA + data engineer | 3-4 days |
| Medium | Conduct analyst usability pilot across multiple case profiles | Validate adoption and workflow efficiency in realistic settings | Product + forensic analyst lead | 2 weeks |
| Low | Extend reporting polish and multi-language/report templates | Improves institutional adoption and communication | UI/reporting engineer | 2-3 days |

### Next validation experiments
| Hypothesis / next question | Method | Success threshold | Resources needed | Timeline |
|---|---|---|---|---|
| Hardening closes admissibility-critical residual risks | Re-run security/forensic audit suite after backlog closure | 0 open critical/high in scoped areas | Security reviewer, QA, audit scripts | 1-2 weeks |
| Integrated workflow materially reduces analyst cycle time across case types | Time-and-motion study with analysts on representative cases | >=25% reduction in analyst handling time versus current baseline process | 5-10 analysts, lab cases, instrumentation | 2-4 weeks |
| Findings remain reproducible across environments and reruns | Repro test matrix (same case, repeated runs, environment variations) | >=95% consistency on key outputs and integrity checks | QA infra and controlled environments | 2 weeks |

---

## 10. Conclusion
FEPD has progressed from a feature-rich but uneven prototype toward an MVP with verified end-to-end operational capability in core workflows and strong movement on forensic admissibility controls. The project now demonstrates practical integrated processing (including thousands of events and hundreds of artifacts in tested runs), passing verification gates for critical remediations, and clearer engineering governance via audits.

The current outcome is GO, conditioned on disciplined hardening of residual high/medium issues and expansion of real-user validation. The strongest next step is to execute a focused hardening sprint with audit re-verification, followed immediately by a structured analyst pilot that quantifies cycle-time reduction and confidence in defensible reporting.

---

## 11. References
[1] FEPD Full System Test Report, docs/FULL_SYSTEM_TEST_REPORT.md, Jan 28, 2026.

[2] FEPD Security and Forensic Soundness Audit Report, SECURITY_FORENSIC_AUDIT.md, Mar 6, 2026.

[3] FEPD Forensic Audit Complete Verification, docs/AUDIT_COMPLETE_VERIFICATION.md, Jan 11, 2026.

[4] FEPD Subsystem Audit Report, SUBSYSTEM_AUDIT_REPORT.md, 2025.

[5] FEPD Complete Implementation Status, docs/COMPLETE_STATUS.md.

[6] FEPD ML/Analytics Deep Audit Report, AUDIT_REPORT.md.

[7] FEPD Project Summary, docs/PROJECT_SUMMARY.md.

---

## Appendix A. Claim-to-evidence traceability matrix
| Claim ID | Claim statement | Evidence type | Evidence link or appendix item | Where discussed in report |
|---|---|---|---|---|
| C1 | Core integrated workflow runs successfully on real case data path | System execution metrics/logs | docs/FULL_SYSTEM_TEST_REPORT.md | Sections 1, 6, 7 |
| C2 | Critical remediation work was verified by tests | Test suite outcomes | docs/AUDIT_COMPLETE_VERIFICATION.md | Sections 6, 7 |
| C3 | Security/forensic controls are strong but require further hardening in specific areas | Audit findings and recommendations | SECURITY_FORENSIC_AUDIT.md | Sections 7, 8, 9 |
| C4 | Architecture and subsystem capability are substantial with integration lessons learned | Subsystem and implementation reports | SUBSYSTEM_AUDIT_REPORT.md; docs/COMPLETE_STATUS.md | Sections 3, 5, 6 |

---

## Appendix B. Reproducibility / build-and-run notes
| Item | What to include |
|---|---|
| Repository structure | Top-level folders include src, docs, config, tests, scripts, models, data, cases; case-focused outputs in case directories and output paths |
| Software dependencies | Python environment with requirements from requirements.txt and optional domain libraries (forensics parsers, ML stack, visualization, Qt UI stack as used by project) |
| Hardware dependencies | Workstation-class host for large evidence images; storage sized for disk images and extracted artifacts |
| Steps to run / build | 1) Activate venv 2) Install requirements 3) Launch main.py 4) Select/open case 5) Ingest/process evidence 6) Validate outputs and reports |
| Expected outputs | Case metadata, artifact/event outputs, timeline/analytics views, chain-of-custody logs, integrity records, and generated reports |

---

## Appendix C. Instruments, forms, and consent
Project repository includes technical validation evidence (audits, test reports, implementation docs). Formal interview/survey/consent instruments are not centrally packaged in this report set and should be added for extended human-subject validation phases.

---

## CS Annex: Threat model, authorized scope, safe testbed, exploit/defense evidence, severity rating

### CS-1. Threat model
Assets:
- Raw evidence files and extracted artifacts
- Chain-of-custody logs and integrity metadata
- ML models, predictions, and report outputs

Adversaries:
- Internal malicious actor with local file access
- External attacker with ability to tamper model/artifact files before load
- Unintentional operator error causing integrity or reproducibility breakage

Attack surfaces:
- Model deserialization paths
- Case/evidence path handling and filesystem operations
- Concurrency-sensitive registries/datastores
- Timestamp normalization and timeline reconstruction logic

Primary security objectives:
- Integrity, traceability, reproducibility, and non-repudiation of forensic outcomes

### CS-2. Authorized test scope
In-scope:
- Static and dynamic analysis of repository code paths
- Controlled execution of test suites and full-system case runs
- Verification of integrity and chain-of-custody logic

Out-of-scope:
- Offensive testing on production systems or third-party environments
- Real-world exploitation against unauthorized infrastructure

Authorization posture:
- Project-internal audit and verification artifacts indicate testing was conducted in controlled development/test context.

### CS-3. Safe testbed
- Local/offline development workspace with synthetic or authorized case artifacts
- Explicit forensic-safe workflow emphasis in project docs
- No recommendation to execute unsafe payloads outside controlled scope

### CS-4. Exploit/defense evidence
Exploit classes evidenced in audits:
- Unsafe deserialization risk via model persistence loading in specific modules (documented critical/high findings)
- Path and concurrency weaknesses in specific components (documented high findings)
- Forensic consistency weaknesses (for example timestamp handling) documented and partially remediated

Defensive controls evidenced:
- Chain-of-custody logging architecture with hash chaining
- Evidence integrity verification workflow
- ML integrity binding work and verification tests
- Multi-phase fix-and-verify loops with explicit test results

### CS-5. Severity rating summary
| Severity | Representative issue types | Current status |
|---|---|---|
| Critical | Model loading safety, admissibility-critical integrity gaps (historical) | Addressed in scoped critical remediation sets; continue continuous verification |
| High | Registry race conditions, residual hardening gaps, inconsistent handling in edge paths | Partially open backlog |
| Medium | Operational controls and consistency improvements | Planned backlog |
| Low | Documentation/UX polish and non-critical enhancements | Ongoing |

### CS-6. Recommended security continuation plan
1. Enforce safe model serialization and signed/hash-verified model loading path globally.
2. Complete thread-safe registry/data write controls and atomic persistence patterns.
3. Standardize UTC timestamp policy across all components.
4. Add continuous security regression tests in CI for critical forensic controls.
5. Maintain threat-model updates whenever new parser, model, or ingestion channel is introduced.
