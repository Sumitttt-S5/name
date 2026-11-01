import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowUpRight,
  Bell,
  CheckCircle2,
  ChevronRight,
  Clock3,
  CloudUpload,
  FileArchive,
  FileCode2,
  FileSearch,
  Fingerprint,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  Menu,
  Package,
  Radar,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Upload,
  X,
  Zap,
} from "lucide-react";

import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

const STAGES = [
  {
    key: "stage_1_name_and_lie_detector",
    name: "Name & Lie Detector",
    description: "Package identity and typosquatting analysis",
    icon: Fingerprint,
  },
  {
    key: "stage_2_password_and_gibberish_tracker",
    name: "Password & Gibberish Tracker",
    description: "Static analysis and sensitive-data flow",
    icon: FileCode2,
  },
  {
    key: "stage_3_update_hijack_detector",
    name: "Update Hijack Detector",
    description: "Version-to-version behaviour changes",
    icon: RefreshCw,
  },
  {
    key: "stage_4_fake_bait_sandbox",
    name: "Fake-Bait Sandbox",
    description: "Runtime behaviour and sandbox evidence",
    icon: Radar,
  },
  {
    key: "stage_5_false_alarm_filter",
    name: "Smart False-Alarm Filter",
    description: "Evidence correlation and calibration",
    icon: ShieldCheck,
  },
  {
    key: "stage_6_ai_reporter",
    name: "AI Translator & Reporter",
    description: "Human-readable explanations and reports",
    icon: Sparkles,
  },
];

const IMPLEMENTATION_STATUS = [
  {
    name: "Stage 1 — Name & Lie Detector",
    status: "IMPLEMENTED",
    description:
      "Checks package identity, suspicious name similarities, and README/package-name inconsistencies.",
  },
  {
    name: "Stage 2 — Password & Gibberish Tracker",
    status: "PARTIAL",
    description:
      "Uses Python AST inspection and basic taint tracking to identify potentially risky code and data flows.",
  },
  {
    name: "Stage 3 — Update Hijack Detector",
    status: "PARTIAL",
    description:
      "Compares package versions and detects behaviour changes. Installation-file comparison is still being verified through the API.",
  },
  {
    name: "Stage 4 — Fake-Bait Sandbox",
    status: "IMPLEMENTED",
    description:
      "Provides a separate Docker-based runtime analysis endpoint for observing package behaviour.",
  },
  {
    name: "Stage 5 — Smart False-Alarm Filter",
    status: "IMPLEMENTED",
    description:
      "Combines available analysis evidence and applies risk classification to reduce misleading alerts.",
  },
  {
    name: "Stage 6 — AI Translator & Reporter",
    status: "PLANNED",
    description:
      "Planned feature for AI-generated plain-language explanations and enhanced security reports.",
  },
];

function ImplementationRoadmap() {
  return (
    <section className="implementation-roadmap">
      <div className="roadmap-heading">
        <div>
          <h2>Development Roadmap</h2>
          <p>
            Six detection stages: what is working, what is partially
            implemented, and what remains to be developed.
          </p>
        </div>
        <ShieldCheck size={23} />
      </div>

      <div className="roadmap-grid">
        {IMPLEMENTATION_STATUS.map((stage, index) => (
          <div className="roadmap-stage" key={stage.name}>
            <div className="roadmap-stage-icon">
              <span>{String(index + 1).padStart(2, "0")}</span>
            </div>

            <div className="roadmap-stage-content">
              <strong>{stage.name}</strong>
              <p>{stage.description}</p>

              <span
                className={`roadmap-status ${
                  stage.status === "IMPLEMENTED"
                    ? "implemented"
                    : stage.status === "PARTIAL"
                      ? "partial"
                      : "planned"
                }`}
              >
                {stage.status === "IMPLEMENTED"
                  ? "✓ IMPLEMENTED"
                  : stage.status === "PARTIAL"
                    ? "◐ PARTIALLY IMPLEMENTED"
                    : "○ PLANNED"}
              </span>
            </div>
          </div>
        ))}
      </div>

      <div className="roadmap-legend">
        <span><i className="roadmap-dot green" /> Implemented</span>
        <span><i className="roadmap-dot orange" /> Partially implemented</span>
        <span><i className="roadmap-dot grey" /> Planned / not implemented</span>
      </div>
    </section>
  );
}


function formatSeverity(value) {
  return (value || "UNKNOWN").toUpperCase();
}

function StatusPill({ status }) {
  const normalized = (status || "UNKNOWN").toUpperCase();

  return (
    <span className={`status-pill status-${normalized.toLowerCase()}`}>
      <span className="status-dot" />
      {normalized.replaceAll("_", " ")}
    </span>
  );
}

function SeverityPill({ severity }) {
  const value = formatSeverity(severity);

  return (
    <span className={`severity-pill severity-${value.toLowerCase()}`}>
      {value}
    </span>
  );
}

function EmptyState({ icon: Icon = FileSearch, title, description }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        <Icon size={25} />
      </div>
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}

function App() {
  const [activePage, setActivePage] = useState("overview");
  const [backendOnline, setBackendOnline] = useState(false);

  // Main package scan
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanEntrypoint, setScanEntrypoint] = useState(
    "sample_package.py"
  );
  const [dragging, setDragging] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Stage 3: Version comparison state
  const [baselineFile, setBaselineFile] = useState(null);
  const [candidateFile, setCandidateFile] = useState(null);
  const [baselineVersion, setBaselineVersion] = useState("");
  const [candidateVersion, setCandidateVersion] = useState("");
  const [comparing, setComparing] = useState(false);
  const [comparisonError, setComparisonError] = useState("");
  const [comparisonResult, setComparisonResult] = useState(null);

  // Stage 4: Fake-Bait Sandbox state
  const [sandboxFile, setSandboxFile] = useState(null);
  const [sandboxEntrypoint, setSandboxEntrypoint] = useState(
    "sample_package.py"
  );
  const [sandboxRunning, setSandboxRunning] = useState(false);
  const [sandboxError, setSandboxError] = useState("");
  const [sandboxResult, setSandboxResult] = useState(null);

  // Check whether the backend is running.
  useEffect(() => {
    let mounted = true;

    const checkBackend = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/health`);

        if (mounted) {
          setBackendOnline(response.ok);
        }
      } catch {
        if (mounted) {
          setBackendOnline(false);
        }
      }
    };

    checkBackend();

    const interval = setInterval(checkBackend, 10000);

    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  // Validate and select the uploaded Python package.
  const chooseFile = (file) => {
    if (!file) return;

    const validExtensions = [".whl", ".zip", ".tar.gz", ".tgz"];
    const lowerName = file.name.toLowerCase();

    const valid = validExtensions.some((extension) =>
      lowerName.endsWith(extension)
    );

    if (!valid) {
      setError(
        "Unsupported file. Upload a .whl, .zip, .tar.gz or .tgz archive."
      );
      setSelectedFile(null);
      return;
    }

    if (file.size > 50 * 1024 * 1024) {
      setError("File exceeds the 50 MB upload limit.");
      setSelectedFile(null);
      return;
    }

    setError("");
    setSelectedFile(file);
    setResult(null);
  };

  // Handle drag-and-drop uploads.
  const handleDrop = (event) => {
    event.preventDefault();
    setDragging(false);
    chooseFile(event.dataTransfer.files?.[0]);
  };

  // Main scan: static analysis + runtime analysis + correlation.
  const startScan = async () => {
    if (!selectedFile || scanning) return;

    if (!scanEntrypoint.trim()) {
      setError("Please provide the Python entrypoint for runtime analysis.");
      return;
    }

    setScanning(true);
    setError("");
    setResult(null);

    try {
      const formData = new FormData();

      formData.append("file", selectedFile);
      formData.append("entrypoint", scanEntrypoint.trim());

      const response = await fetch(`${API_BASE}/api/full-analysis`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "The complete package analysis failed."
        );
      }

      setResult(data);
      setScanHistory((previous) => [data, ...previous]);
      setActivePage("overview");
    } catch (scanError) {
      setError(
        scanError.message ||
          "Could not connect to the backend. Check that FastAPI is running."
      );
    } finally {
      setScanning(false);
    }
  };

  // Download the complete analysis report.
  const downloadReport = () => {
    if (!result) return;

    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = `${
      result.package?.name || result.package_name || "package"
    }-full-analysis-report.json`;

    anchor.click();
    URL.revokeObjectURL(url);
  };

  // Stage 3: Compare two versions of a package.
  const startVersionComparison = async () => {
    if (
      !baselineFile ||
      !candidateFile ||
      !baselineVersion.trim() ||
      !candidateVersion.trim() ||
      comparing
    ) {
      return;
    }

    setComparing(true);
    setComparisonError("");
    setComparisonResult(null);

    try {
      const formData = new FormData();

      formData.append("baseline_file", baselineFile);
      formData.append("candidate_file", candidateFile);
      formData.append("baseline_version", baselineVersion.trim());
      formData.append("candidate_version", candidateVersion.trim());

      const response = await fetch(
        `${API_BASE}/api/compare-versions`,
        {
          method: "POST",
          body: formData,
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Version comparison failed."
        );
      }

      setComparisonResult(data);
    } catch (comparisonError) {
      setComparisonError(
        comparisonError.message ||
          "Could not connect to the backend."
      );
    } finally {
      setComparing(false);
    }
  };

  // Stage 4: Execute the uploaded package in the Docker sandbox.
  const startSandbox = async () => {
    if (!sandboxFile) {
      setSandboxError("Please select a Python package archive.");
      return;
    }

    if (!sandboxEntrypoint.trim()) {
      setSandboxError("Please provide the Python entrypoint.");
      return;
    }

    setSandboxRunning(true);
    setSandboxError("");
    setSandboxResult(null);

    try {
      const formData = new FormData();

      formData.append("file", sandboxFile);
      formData.append("entrypoint", sandboxEntrypoint.trim());

      const response = await fetch(`${API_BASE}/api/sandbox`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Sandbox execution failed."
        );
      }

      setSandboxResult(data);
    } catch (sandboxRequestError) {
      setSandboxError(
        sandboxRequestError.message ||
          "Could not connect to the sandbox backend."
      );
    } finally {
      setSandboxRunning(false);
    }
  };

  // Download the runtime sandbox report.
  const downloadSandboxReport = () => {
    if (!sandboxResult) return;

    const blob = new Blob(
      [JSON.stringify(sandboxResult, null, 2)],
      { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = "supply-chain-guardian-runtime-report.json";
    anchor.click();

    URL.revokeObjectURL(url);
  };

  // Download the version-comparison report.
  const downloadComparisonReport = () => {
    if (!comparisonResult) return;

    const blob = new Blob(
      [JSON.stringify(comparisonResult, null, 2)],
      { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = "version-comparison-report.json";
    anchor.click();

    URL.revokeObjectURL(url);
  };

  // Dashboard data: use the actual unified-analysis response structure.
  const findings = Array.isArray(result?.findings)
    ? result.findings
    : [];

  const score =
    result?.risk?.context_adjusted_score ??
    result?.risk?.score ??
    0;

  const severity =
    result?.risk?.severity ??
    result?.risk?.context_adjusted_severity ??
    "UNKNOWN";

  const completedStages = [];

  if (result?.static_analysis) {
    completedStages.push("stage_2_password_and_gibberish_tracker");
  }

  if (result?.runtime_analysis) {
    completedStages.push("stage_4_fake_bait_sandbox");
  }

  if (result?.false_alarm_filter) {
    completedStages.push("stage_5_false_alarm_filter");
  }

  const navigate = (page) => {
    setActivePage(page);
    setMobileMenuOpen(false);
  };

  // Main package upload panel.
  const renderUploadPanel = () => (
    <div className="upload-panel">
      <div className="section-heading">
        <div>
          <h2>Upload Package</h2>
          <p>
            Run static analysis, runtime inspection and behavioural
            correlation on a Python package.
          </p>
        </div>
        <FileArchive size={22} />
      </div>

      <div
        className={`drop-zone ${dragging ? "dragging" : ""} ${
          selectedFile ? "has-file" : ""
        }`}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
      >
        <div className="drop-icon">
          <CloudUpload size={34} />
        </div>

        <h3>
          {selectedFile
            ? selectedFile.name
            : "Drop your package archive here"}
        </h3>

        <p>
          {selectedFile
            ? `${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB`
            : "Upload a .zip, .tar.gz, .tgz or .whl package"}
        </p>

        <label className="browse-button">
          Browse Files
          <input
            type="file"
            accept=".zip,.tar,.gz,.tgz,.whl"
            onChange={(event) =>
              chooseFile(event.target.files?.[0])
            }
            hidden
          />
        </label>
      </div>

      <div className="sandbox-field scan-entrypoint-field">
        <label htmlFor="scan-entrypoint">
          Python entrypoint for runtime analysis
        </label>

        <input
          id="scan-entrypoint"
          type="text"
          value={scanEntrypoint}
          placeholder="e.g. sample_package.py"
          onChange={(event) =>
            setScanEntrypoint(event.target.value)
          }
        />

        <span className="sandbox-field-help">
          Path relative to the extracted package root. Example:
          sample_package.py
        </span>
      </div>

      {error && (
        <div className="error-message">
          <AlertTriangle size={17} />
          <span>{error}</span>
        </div>
      )}

      <div className="upload-actions">
        <button
          className="primary-button"
          onClick={startScan}
          disabled={!selectedFile || scanning || !backendOnline}
        >
          {scanning ? (
            <>
              <LoaderCircle size={17} className="spin" />
              Running Complete Analysis...
            </>
          ) : (
            <>
              <ShieldCheck size={17} />
              Start Complete Security Scan
            </>
          )}
        </button>

        {selectedFile && (
          <button
            className="secondary-button"
            onClick={() => {
              setSelectedFile(null);
              setError("");
              setResult(null);
            }}
            disabled={scanning}
          >
            <X size={16} />
            Remove File
          </button>
        )}
      </div>

      <div className="upload-note">
        <LockKeyhole size={15} />
        <span>
          Combines static package inspection with Docker-isolated
          runtime analysis. Runtime execution is restricted and does
          not guarantee detection of every malicious behaviour.
        </span>
      </div>

      {!backendOnline && (
        <p className="backend-hint">
          Backend is offline. Start FastAPI before running the scan.
        </p>
      )}
    </div>
  );
    // Render the complete security analysis report.
  const renderResults = () => {
    if (!result) {
      return (
        <div className="results-empty">
          <EmptyState
            icon={<FileSearch size={30} />}
            title="No scan results yet"
            description="Upload a Python package and start a scan to view its complete security analysis."
          />
        </div>
      );
    }

    const resultFindings = Array.isArray(result.findings)
      ? result.findings
      : findings;

    const riskData = result.risk || {};

    const resultScore =
      riskData.context_adjusted_score ??
      riskData.score ??
      result.risk_score ??
      result.score ??
      0;

    const riskLevel =
      riskData.context_adjusted_severity ||
      riskData.severity ||
      result.risk_level ||
      (resultScore >= 70
        ? "CRITICAL"
        : resultScore >= 45
          ? "HIGH"
          : resultScore >= 20
            ? "MEDIUM"
            : "LOW");

    const staticData = result.static_analysis || {};

    const filesAnalyzed =
      staticData.coverage?.files_analyzed ??
      staticData.files_analyzed ??
      staticData.summary?.files_analyzed ??
      result.files_analyzed ??
      result.statistics?.files_analyzed ??
      0;

    const filesDiscovered =
      staticData.coverage?.files_discovered ??
      staticData.files_discovered ??
      staticData.summary?.files_discovered ??
      result.files_discovered ??
      result.statistics?.files_discovered ??
      0;

    const runtimeData = result.runtime_analysis || {};

    const runtimeReport =
      runtimeData.report || runtimeData;

    const runtimeEvents = Array.isArray(runtimeData.events)
      ? runtimeData.events
      : Array.isArray(runtimeData.runtime_events)
        ? runtimeData.runtime_events
        : Array.isArray(runtimeReport.events)
          ? runtimeReport.events
          : [];

    const correlationData = result.correlation || {};
    const correlationSummary = correlationData.summary || {};

    const correlations = Array.isArray(
      correlationData.correlated_behaviours
    )
      ? correlationData.correlated_behaviours
      : Array.isArray(correlationData.correlations)
        ? correlationData.correlations
        : [];

    const filterData = result.false_alarm_filter || {};
    const filterSummary = filterData.summary || {};

    const suspiciousCount =
      filterSummary.suspicious ??
      filterSummary.suspicious_findings ??
      0;

    const reviewCount =
      filterSummary.needs_review ??
      filterSummary.needs_review_findings ??
      0;

    const informationalCount =
      filterSummary.informational ??
      filterSummary.informational_findings ??
      0;

    const duplicateCount =
      filterSummary.duplicates_removed ??
      filterSummary.duplicate_count ??
      0;

    const formatEvidence = (evidence) => {
      if (Array.isArray(evidence)) {
        return evidence
          .map((item) =>
            typeof item === "object"
              ? JSON.stringify(item)
              : String(item)
          )
          .join(" | ");
      }

      if (typeof evidence === "object" && evidence !== null) {
        return JSON.stringify(evidence);
      }

      return String(evidence);
    };

    const getEventDescription = (event) => {
      if (typeof event.details === "string") {
        return event.details;
      }

      if (event.details && typeof event.details === "object") {
        return Object.entries(event.details)
          .map(
            ([key, value]) =>
              `${key}: ${
                typeof value === "object"
                  ? JSON.stringify(value)
                  : String(value)
              }`
          )
          .join(" | ");
      }

      return (
        event.description ||
        event.message ||
        event.event_type ||
        "Runtime event detected"
      );
    };

    return (
      <div className="results-container">

        {/* REPORT HEADER */}
        <div className="results-header">
          <div>
            <div className="eyebrow">COMPLETE SECURITY ANALYSIS</div>
            <h2>Scan Results</h2>
            <p>
              {result.package?.name ||
                result.package_name ||
                result.filename ||
                "Uploaded package"}
            </p>
          </div>

          <button
            className="secondary-button"
            onClick={downloadReport}
          >
            <ArrowDownToLine size={17} />
            Download JSON
          </button>
        </div>

        {/* TOP LEVEL METRICS */}
        <div className="results-overview-grid">

          <div className="result-stat-card risk-card">
            <div className="stat-card-top">
              <span>Overall Risk Score</span>
              <ShieldAlert size={20} />
            </div>

            <div className="risk-score-row">
              <span className="risk-score-value">
                {resultScore}
              </span>
              <span className="risk-score-total">/ 100</span>
            </div>

            <StatusPill status={riskLevel} />

            <div className="risk-progress">
              <div
                className={`risk-progress-fill ${String(
                  riskLevel
                ).toLowerCase()}`}
                style={{
                  width: `${Math.max(
                    0,
                    Math.min(100, Number(resultScore) || 0)
                  )}%`,
                }}
              />
            </div>
          </div>

          <div className="result-stat-card">
            <div className="stat-card-top">
              <span>Total Findings</span>
              <AlertTriangle size={20} />
            </div>

            <div className="stat-number">
              {resultFindings.length}
            </div>

            <span className="stat-description">
              Combined security findings
            </span>
          </div>

          <div className="result-stat-card">
            <div className="stat-card-top">
              <span>Files Analyzed</span>
              <FileCode2 size={20} />
            </div>

            <div className="stat-number">
              {filesAnalyzed}
            </div>

            <span className="stat-description">
              Out of {filesDiscovered} discovered
            </span>
          </div>

          <div className="result-stat-card">
            <div className="stat-card-top">
              <span>Analysis Status</span>
              <Activity size={20} />
            </div>

            <div className="stat-status">
              <CheckCircle2 size={20} />
              {result.analysis_status ||
                result.scan_status ||
                result.status ||
                "COMPLETED"}
            </div>

            <span className="stat-description">
              Analysis process finished
            </span>
          </div>

        </div>

        {/* DETECTION PIPELINE */}
        <div className="stage-progress-card">
          <div className="section-heading">
            <div>
              <h3>Detection Pipeline</h3>
              <p>
                Implementation status of the security stages.
              </p>
            </div>

            <Radar size={21} />
          </div>

          <div className="stage-list">
            {STAGES.map((stage) => {
              const stageResult = Array.isArray(result.stages)
                ? result.stages.find(
                    (item) =>
                      item.stage === stage.key ||
                      item.stage_name === stage.name
                  )
                : null;

              let stageStatus =
                stageResult?.status ||
                result.stage_status?.[stage.key] ||
                (completedStages.includes(stage.key)
                  ? "COMPLETED"
                  : "NOT_AVAILABLE");

              stageStatus = String(stageStatus).toUpperCase();

              // Stage 4 is completed when the runtime analysis
              // returned a report, even if it contains zero events.
              if (
                stage.key === "stage_4_fake_bait_sandbox" &&
                result.runtime_analysis
              ) {
                stageStatus =
                  String(runtimeData.status || "COMPLETED").toUpperCase();
              }

              // Stage 5 is completed when the filter returned a result.
              if (
                stage.key === "stage_5_false_alarm_filter" &&
                result.false_alarm_filter
              ) {
                stageStatus = "COMPLETED";
              }

              return (
                <div className="stage-item" key={stage.key}>
                  <div className="stage-item-icon">
                    {stageStatus === "COMPLETED" ||
                    stageStatus === "PARTIAL" ? (
                      <CheckCircle2 size={17} />
                    ) : (
                      <Clock3 size={17} />
                    )}
                  </div>

                  <div className="stage-item-info">
                    <strong>{stage.name}</strong>
                    <span>{stage.description}</span>
                  </div>

                  <StatusPill status={stageStatus} />
                </div>
              );
            })}
          </div>
        </div>

        {/* STATIC + RUNTIME FINDINGS */}
        <div className="findings-section">
          <div className="section-heading">
            <div>
              <h3>Security Findings</h3>
              <p>
                Combined evidence collected during static and
                runtime analysis.
              </p>
            </div>

            <span className="finding-count">
              {resultFindings.length} findings
            </span>
          </div>

          {resultFindings.length === 0 ? (
            <EmptyState
              icon={<ShieldCheck size={30} />}
              title="No suspicious behaviour detected"
              description="The scanner did not identify findings in the analyzed package. This does not guarantee that the package is completely safe."
            />
          ) : (
            <div className="findings-list">
              {resultFindings.map((finding, index) => (
                <div
                  className="finding-card"
                  key={
                    finding.finding_id ||
                    finding.fingerprint ||
                    `${finding.rule_id}-${index}`
                  }
                >
                  <div className="finding-card-header">
                    <div className="finding-title-group">
                      <AlertTriangle size={18} />

                      <div>
                        <h4>
                          {finding.title ||
                            finding.rule_id ||
                            "Suspicious behaviour"}
                        </h4>

                        <span className="finding-rule">
                          {finding.rule_id || "UNKNOWN-RULE"}
                        </span>
                      </div>
                    </div>

                    <SeverityPill
                      severity={finding.severity || "LOW"}
                    />
                  </div>

                  <p className="finding-description">
                    {finding.description ||
                      "The scanner identified a potentially suspicious code pattern."}
                  </p>

                  {finding.evidence && (
                    <div className="finding-evidence">
                      <span>Evidence</span>
                      <code>
                        {formatEvidence(finding.evidence)}
                      </code>
                    </div>
                  )}

                  {finding.runtime_category && (
                    <div className="finding-footer">
                      <span>
                        Runtime category: {finding.runtime_category}
                      </span>
                    </div>
                  )}

                  <div className="finding-footer">
                    <span>
                      <FileCode2 size={14} />
                      {finding.file || "Runtime / Unknown file"}
                      {finding.line
                        ? ` : line ${finding.line}`
                        : ""}
                    </span>

                    <span>
                      Confidence: {finding.confidence || "UNKNOWN"}
                    </span>

                    {typeof finding.score_contribution ===
                      "number" && (
                      <span>
                        Score contribution:{" "}
                        {finding.score_contribution}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* RUNTIME ANALYSIS */}
        <div className="stage-progress-card">
          <div className="section-heading">
            <div>
              <div className="eyebrow">
                STAGE 4 · FAKE-BAIT SANDBOX
              </div>

              <h3>Runtime Analysis</h3>

              <p>
                Events observed during isolated package execution.
              </p>
            </div>

            <Radar size={21} />
          </div>

          {runtimeEvents.length === 0 ? (
            <EmptyState
              icon={<Activity size={28} />}
              title="No runtime events available"
              description="The runtime report did not contain any events or the sandbox did not return event data."
            />
          ) : (
            <div className="findings-list">
              {runtimeEvents.map((event, index) => (
                <div
                  className="finding-card"
                  key={event.event_id || `${event.event_type}-${index}`}
                >
                  <div className="finding-card-header">
                    <div className="finding-title-group">
                      <Activity size={18} />

                      <div>
                        <h4>
                          {event.event_type ||
                            event.type ||
                            "Runtime event"}
                        </h4>

                        <span className="finding-rule">
                          {event.category || "Runtime observation"}
                        </span>
                      </div>
                    </div>

                    <SeverityPill
                      severity={event.severity || "LOW"}
                    />
                  </div>

                  <p className="finding-description">
                    {getEventDescription(event)}
                  </p>

                  {event.path && (
                    <div className="finding-evidence">
                      <span>Path</span>
                      <code>{String(event.path)}</code>
                    </div>
                  )}

                  {event.destination && (
                    <div className="finding-evidence">
                      <span>Destination</span>
                      <code>
                        {formatEvidence(event.destination)}
                      </code>
                    </div>
                  )}

                  <div className="finding-footer">
                    <span>
                      Confidence: {event.confidence || "OBSERVED"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {runtimeData.exit_code !== undefined && (
            <div className="hash-note">
              <Activity size={15} />
              <span>
                Sandbox exit code: {runtimeData.exit_code}
              </span>
            </div>
          )}
        </div>

        {/* BEHAVIOURAL CORRELATION */}
        <div className="stage-progress-card">
          <div className="section-heading">
            <div>
              <div className="eyebrow">
                BEHAVIOURAL CORRELATION
              </div>

              <h3>Static vs Runtime Behaviour</h3>

              <p>
                Compare code patterns identified statically with
                behaviours observed during runtime execution.
              </p>
            </div>

            <Fingerprint size={21} />
          </div>

          <div className="comparison-summary-grid">
            <div className="comparison-summary-card">
              <span>Static Findings</span>
              <strong>
                {correlationSummary.static_findings_count ??
                  correlationData.static_findings_count ??
                  staticData.findings?.length ??
                  0}
              </strong>
              <p>Detected through code inspection</p>
            </div>

            <div className="comparison-summary-card">
              <span>Runtime Events</span>
              <strong>
                {correlationSummary.runtime_events_count ??
                  correlationData.runtime_events_count ??
                  runtimeEvents.length}
              </strong>
              <p>Observed during execution</p>
            </div>

            <div className="comparison-summary-card">
              <span>Correlated Behaviours</span>
              <strong>
                {correlationSummary.correlated_behaviours_count ??
                  correlationData.correlated_behaviours_count ??
                  correlations.length}
              </strong>
              <p>Matching behaviour categories</p>
            </div>
          </div>

          {correlations.length === 0 ? (
            <p className="comparison-empty">
              No matching static and runtime behaviour categories
              were reported.
            </p>
          ) : (
            <div className="findings-list">
              {correlations.map((item, index) => (
                <div
                  className="finding-card"
                  key={`${item.category || item.behaviour || "correlation"}-${index}`}
                >
                  <div className="finding-card-header">
                    <div className="finding-title-group">
                      <Fingerprint size={18} />

                      <div>
                        <h4>
                          {item.category ||
                            item.behaviour ||
                            item.behaviour_category ||
                            "Correlated behaviour"}
                        </h4>

                        <span className="finding-rule">
                          {item.correlation_type ||
                            "Behavioural category co-occurrence"}
                        </span>
                      </div>
                    </div>

                    <StatusPill
                      status={item.confidence || "LOW"}
                    />
                  </div>

                  <p className="finding-description">
                    {item.description ||
                      item.explanation ||
                      item.reason ||
                      "A related category of behaviour appeared in both static and runtime analysis."}
                  </p>

                  <div className="hash-note">
                    <LockKeyhole size={15} />
                    <span>
                      Category co-occurrence does not establish
                      exact source-level causation.
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* FALSE ALARM FILTER */}
        <div className="stage-progress-card">
          <div className="section-heading">
            <div>
              <div className="eyebrow">
                STAGE 5 · SMART FALSE-ALARM FILTER
              </div>

              <h3>Finding Classification</h3>

              <p>
                Context-aware classification of the combined
                security findings.
              </p>
            </div>

            <ShieldCheck size={21} />
          </div>

          <div className="comparison-summary-grid">
            <div className="comparison-summary-card introduced">
              <span>Suspicious</span>
              <strong>{suspiciousCount}</strong>
              <p>Findings requiring attention</p>
            </div>

            <div className="comparison-summary-card persistent">
              <span>Needs Review</span>
              <strong>{reviewCount}</strong>
              <p>Findings requiring investigation</p>
            </div>

            <div className="comparison-summary-card removed">
              <span>Informational</span>
              <strong>{informationalCount}</strong>
              <p>Lower-priority observations</p>
            </div>
          </div>

          <div className="hash-comparison-card">
            <div className="hash-row">
              <span>Eligible findings</span>
              <strong>
                {filterSummary.eligible_findings ??
                  filterSummary.eligible ??
                  resultFindings.length}
              </strong>
            </div>

            <div className="hash-row">
              <span>Duplicates removed</span>
              <strong>{duplicateCount}</strong>
            </div>

            <div className="hash-row">
              <span>Classification status</span>
              <StatusPill
                status={filterData.status || "COMPLETED"}
              />
            </div>
          </div>
        </div>

      </div>
    );
  };
    // Stage 3: Render version comparison results.
  const renderVersionComparison = () => {
    const comparison = comparisonResult;

    if (!comparison) {
      return (
        <div className="results-empty">
          <EmptyState
            icon={<RefreshCw size={30} />}
            title="No version comparison yet"
            description="Upload two versions of the same Python package to identify newly introduced, removed, and persistent behaviours."
          />
        </div>
      );
    }

    const baseline = comparison.baseline || {};
    const candidate = comparison.candidate || {};
    const summary = comparison.summary || {};

    const introduced = comparison.introduced_behaviours || [];
    const removed = comparison.removed_behaviours || [];
    const persistent = comparison.persistent_behaviours || [];

    const renderBehaviourList = (items, emptyMessage) => {
      if (!items.length) {
        return (
          <p className="comparison-empty">{emptyMessage}</p>
        );
      }

      return (
        <div className="comparison-findings-list">
          {items.map((finding, index) => (
            <div
              className="comparison-finding"
              key={
                finding.fingerprint ||
                finding.rule_id ||
                `${finding.title}-${index}`
              }
            >
              <div className="comparison-finding-heading">
                <div>
                  <strong>
                    {finding.title || "Detected behaviour"}
                  </strong>
                  <span className="finding-rule">
                    {finding.rule_id || "UNKNOWN-RULE"}
                  </span>
                </div>
                <SeverityPill
                  severity={finding.severity || "LOW"}
                />
              </div>

              <p>
                {finding.description ||
                  "The scanner identified a behaviour in this package version."}
              </p>

              {finding.evidence && (
                <div className="finding-evidence">
                  <span>Evidence</span>
                  <code>
                    {Array.isArray(finding.evidence)
                      ? finding.evidence.join("; ")
                      : String(finding.evidence)}
                  </code>
                </div>
              )}

              <div className="finding-footer">
                <span>
                  <FileCode2 size={14} />
                  {finding.file || "Unknown file"}
                  {finding.line
                    ? ` : line ${finding.line}`
                    : ""}
                </span>
                <span>
                  Confidence: {finding.confidence || "UNKNOWN"}
                </span>
              </div>
            </div>
          ))}
        </div>
      );
    };

    return (
      <div className="comparison-results">
        <div className="results-header">
          <div>
            <div className="eyebrow">
              STAGE 3 · UPDATE HIJACK DETECTOR
            </div>
            <h2>Version Comparison Results</h2>
            <p>
              {comparison.package?.name || "Package"} —{" "}
              {baseline.version || "Baseline"} compared with{" "}
              {candidate.version || "Candidate"}
            </p>
          </div>

          <button
            className="secondary-button"
            onClick={downloadComparisonReport}
          >
            <ArrowDownToLine size={17} />
            Download Report
          </button>
        </div>

        <div className="comparison-status">
          <CheckCircle2 size={18} />
          <span>
            Comparison status:{" "}
            <strong>
              {comparison.status || "COMPLETED"}
            </strong>
          </span>
        </div>

        <div className="comparison-version-grid">
          <div className="version-card">
            <div className="version-card-heading">
              <span>BASELINE VERSION</span>
              <Package size={19} />
            </div>
            <h3>{baseline.version || "Unknown"}</h3>
            <p>Original package version</p>
            <div className="version-file-count">
              <FileCode2 size={15} />
              {baseline.files_analyzed ?? 0} files analyzed
            </div>
          </div>

          <div className="version-arrow">
            <ArrowUpRight size={24} />
          </div>

          <div className="version-card candidate-version">
            <div className="version-card-heading">
              <span>CANDIDATE VERSION</span>
              <Zap size={19} />
            </div>
            <h3>{candidate.version || "Unknown"}</h3>
            <p>New package version</p>
            <div className="version-file-count">
              <FileCode2 size={15} />
              {candidate.files_analyzed ?? 0} files analyzed
            </div>
          </div>
        </div>

        <div className="comparison-summary-grid">
          <div className="comparison-summary-card introduced">
            <span>New Behaviours</span>
            <strong>
              {summary.introduced_behaviours ?? introduced.length}
            </strong>
            <p>Detected only in the candidate version</p>
          </div>

          <div className="comparison-summary-card removed">
            <span>Removed Behaviours</span>
            <strong>
              {summary.removed_behaviours ?? removed.length}
            </strong>
            <p>Detected only in the baseline version</p>
          </div>

          <div className="comparison-summary-card persistent">
            <span>Persistent Behaviours</span>
            <strong>
              {summary.persistent_behaviours ?? persistent.length}
            </strong>
            <p>Detected in both versions</p>
          </div>
        </div>

        <div className="hash-comparison-card">
          <div className="section-heading">
            <div>
              <h3>Artifact Integrity</h3>
              <p>
                SHA-256 hashes calculated from the extracted package contents.
              </p>
            </div>
            <Fingerprint size={21} />
          </div>

          <div className="hash-row">
            <span>Baseline hash</span>
            <code>
              {baseline.artifact_hash || "Not available"}
            </code>
          </div>

          <div className="hash-row">
            <span>Candidate hash</span>
            <code>
              {candidate.artifact_hash || "Not available"}
            </code>
          </div>

          <div className="hash-note">
            <LockKeyhole size={15} />
            <span>
              Different hashes indicate different extracted contents.
              A hash difference alone does not prove malicious activity.
            </span>
          </div>
        </div>

        <div className="comparison-behaviours">
          <div className="section-heading">
            <div>
              <h3>Behaviour Changes</h3>
              <p>
                Review what changed between the two package versions.
              </p>
            </div>
            <Radar size={21} />
          </div>

          <div className="behaviour-section">
            <div className="behaviour-heading">
              <h4>
                <span className="behaviour-dot introduced-dot" />
                Newly Introduced Behaviours
              </h4>
              <span>{introduced.length}</span>
            </div>
            {renderBehaviourList(
              introduced,
              "No newly introduced behaviours were detected."
            )}
          </div>

          <div className="behaviour-section">
            <div className="behaviour-heading">
              <h4>
                <span className="behaviour-dot removed-dot" />
                Removed Behaviours
              </h4>
              <span>{removed.length}</span>
            </div>
            {renderBehaviourList(
              removed,
              "No removed behaviours were detected."
            )}
          </div>

          <div className="behaviour-section">
            <div className="behaviour-heading">
              <h4>
                <span className="behaviour-dot persistent-dot" />
                Persistent Behaviours
              </h4>
              <span>{persistent.length}</span>
            </div>
            {renderBehaviourList(
              persistent,
              "No persistent behaviours were detected."
            )}
          </div>
        </div>

        {(comparison.parse_issues?.baseline?.length > 0 ||
          comparison.parse_issues?.candidate?.length > 0) && (
          <div className="comparison-warning">
            <AlertTriangle size={19} />
            <div>
              <h4>Some files could not be parsed</h4>
              <p>
                Parsing issues may affect the completeness of the comparison.
              </p>

              {comparison.parse_issues?.baseline?.length > 0 && (
                <p>
                  Baseline:{" "}
                  {comparison.parse_issues.baseline.length} issue(s)
                </p>
              )}

              {comparison.parse_issues?.candidate?.length > 0 && (
                <p>
                  Candidate:{" "}
                  {comparison.parse_issues.candidate.length} issue(s)
                </p>
              )}
            </div>
          </div>
        )}

        {comparison.limitations?.length > 0 && (
          <div className="comparison-limitations">
            <h4>Analysis Limitations</h4>
            <ul>
              {comparison.limitations.map((limitation, index) => (
                <li key={index}>{limitation}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  };

  // Stage 4: Render standalone sandbox results.
  const renderSandboxResults = () => {
    if (!sandboxResult) {
      return (
        <div className="sandbox-empty-state">
          <EmptyState
            icon={<Radar size={30} />}
            title="No runtime analysis yet"
            description="Upload a Python package archive and run it inside the isolated Docker sandbox to collect runtime evidence."
          />
        </div>
      );
    }

    const events =
      sandboxResult.events ||
      sandboxResult.runtime_events ||
      sandboxResult.findings ||
      [];

    const severityCounts =
      sandboxResult.severity_counts ||
      sandboxResult.summary?.severity_counts ||
      {};

    const totalEvents =
      sandboxResult.total_events ?? events.length;

    const eventSeverity = (event) =>
      event.severity || event.level || event.risk || "INFO";

    const eventTitle = (event) =>
      event.title ||
      event.event_type ||
      event.type ||
      event.rule_id ||
      "Runtime event";

    const eventDescription = (event) => {
      if (event.description) return event.description;
      if (event.message) return event.message;

      if (typeof event.details === "string") {
        return event.details;
      }

      if (event.details && typeof event.details === "object") {
        return event.details.path
          ? `Accessed path: ${event.details.path}`
          : JSON.stringify(event.details);
      }

      return event.destination ||
        "The sandbox recorded a runtime event.";
    };

    return (
      <div className="sandbox-results">
        <div className="results-header">
          <div>
            <div className="eyebrow">
              STAGE 4 · FAKE-BAIT SANDBOX
            </div>
            <h2>Runtime Analysis Results</h2>
            <p>
              {sandboxResult.package?.name ||
                sandboxFile?.name ||
                "Python package"}
            </p>
          </div>

          <button
            className="secondary-button"
            onClick={downloadSandboxReport}
          >
            <ArrowDownToLine size={17} />
            Download JSON
          </button>
        </div>

        <div className="sandbox-status-banner">
          <div>
            <span className="sandbox-status-label">
              Execution status
            </span>
            <strong>
              {String(
                sandboxResult.execution_status ||
                  sandboxResult.status ||
                  "UNKNOWN"
              ).replaceAll("_", " ")}
            </strong>
          </div>

          <StatusPill
            status={
              sandboxResult.execution_status ||
              sandboxResult.status ||
              "UNKNOWN"
            }
          />
        </div>

        <div className="sandbox-stats-grid">
          <div className="sandbox-stat-card">
            <span>Total runtime events</span>
            <strong>{totalEvents}</strong>
          </div>

          <div className="sandbox-stat-card">
            <span>High severity</span>
            <strong>
              {severityCounts.HIGH ?? severityCounts.high ?? 0}
            </strong>
          </div>

          <div className="sandbox-stat-card">
            <span>Medium severity</span>
            <strong>
              {severityCounts.MEDIUM ?? severityCounts.medium ?? 0}
            </strong>
          </div>

          <div className="sandbox-stat-card">
            <span>Execution duration</span>
            <strong>
              {typeof sandboxResult.duration_seconds === "number"
                ? `${sandboxResult.duration_seconds.toFixed(2)}s`
                : "—"}
            </strong>
          </div>
        </div>

        <div className="sandbox-meta-card">
          <h3>Execution details</h3>

          <div className="sandbox-meta-grid">
            <div>
              <span>Worker</span>
              <strong>
                {sandboxResult.worker || "Docker sandbox worker"}
              </strong>
            </div>

            <div>
              <span>Exit code</span>
              <strong>
                {sandboxResult.exit_code ??
                  sandboxResult.execution?.exit_code ??
                  "—"}
              </strong>
            </div>

            <div>
              <span>Network policy</span>
              <strong>
                {sandboxResult.network_policy || "Not reported"}
              </strong>
            </div>

            <div>
              <span>Report ID</span>
              <strong className="sandbox-mono">
                {sandboxResult.report_id || "Not available"}
              </strong>
            </div>
          </div>
        </div>

        <div className="sandbox-events-section">
          <div className="section-heading">
            <div>
              <h3>Runtime Evidence</h3>
              <p>
                Events observed by the sandbox monitoring layer.
              </p>
            </div>

            <span className="finding-count">
              {events.length} events
            </span>
          </div>

          {events.length === 0 ? (
            <EmptyState
              icon={<ShieldCheck size={30} />}
              title="No runtime events recorded"
              description="The worker returned no event records for this execution. This does not by itself prove that the package is safe."
            />
          ) : (
            <div className="sandbox-event-list">
              {events.map((event, index) => (
                <article
                  className="sandbox-event-card"
                  key={
                    event.event_id ||
                    event.id ||
                    `${eventTitle(event)}-${index}`
                  }
                >
                  <div className="sandbox-event-heading">
                    <div>
                      <h4>
                        {eventTitle(event).replaceAll("_", " ")}
                      </h4>
                      <span>
                        {event.monitor ||
                          event.source ||
                          "Runtime monitor"}
                      </span>
                    </div>

                    <SeverityPill
                      severity={eventSeverity(event)}
                    />
                  </div>

                  <p>{eventDescription(event)}</p>

                  {(event.path ||
                    event.file ||
                    event.destination) && (
                    <div className="sandbox-event-evidence">
                      <span>Evidence</span>
                      <code>
                        {event.path ||
                          event.file ||
                          event.destination}
                      </code>
                    </div>
                  )}

                  {event.timestamp && (
                    <div className="sandbox-event-time">
                      {String(event.timestamp)}
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
        </div>

        {sandboxResult.stdout && (
          <div className="sandbox-output-card">
            <h3>Captured standard output</h3>
            <pre>{sandboxResult.stdout}</pre>
          </div>
        )}

        {sandboxResult.report_file && (
          <p className="sandbox-report-location">
            Report saved by backend:{" "}
            <code>{sandboxResult.report_file}</code>
          </p>
        )}

        {Array.isArray(sandboxResult.limitations) &&
          sandboxResult.limitations.length > 0 && (
            <div className="sandbox-limitations">
              <h3>Monitoring limitations</h3>
              <ul>
                {sandboxResult.limitations.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>
          )}
      </div>
    );
  };

  // Scan history.
  const renderHistory = () => (
    <div className="history-section">
      <div className="section-heading">
        <div>
          <h2>Scan History</h2>
          <p>Review your previous package security scans.</p>
        </div>
        <Clock3 size={22} />
      </div>

      {scanHistory.length === 0 ? (
        <EmptyState
          icon={<FileSearch size={30} />}
          title="No scan history"
          description="Your completed package scans will appear here."
        />
      ) : (
        <div className="history-list">
          {scanHistory.map((item, index) => (
            <div
              className="history-card"
              key={item.id || index}
            >
              <div className="history-card-icon">
                <Package size={21} />
              </div>

              <div className="history-card-info">
                <strong>
                  {item.package?.name ||
                    item.package_name ||
                    item.filename ||
                    "Unknown package"}
                </strong>

                <span>
                  {item.timestamp
                    ? new Date(item.timestamp).toLocaleString()
                    : "Date unavailable"}
                </span>
              </div>

              <div className="history-card-score">
                <strong>
                  {item.risk?.context_adjusted_score ??
                    item.risk?.score ??
                    item.risk_score ??
                    item.score ??
                    0}
                </strong>
                <span>Risk score</span>
              </div>

              <StatusPill
                status={
                  item.risk?.context_adjusted_severity ||
                  item.risk?.severity ||
                  item.risk_level ||
                  "COMPLETED"
                }
              />

              <button
                className="icon-button"
                title="View scan report"
                onClick={() => {
                  setResult(item);
                  setActivePage("overview");
                }}
              >
                <ChevronRight size={19} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  // Main application layout.
  return (
    <div className="app-shell">
      {/* Mobile sidebar overlay */}
      {mobileMenuOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`sidebar ${mobileMenuOpen ? "sidebar-open" : ""}`}>
        <div className="sidebar-brand">
          <div className="brand-icon">
            <Shield size={25} />
          </div>

          <div className="brand-text">
            <h1>KodKavach</h1>
            <span></span>
          </div>

          <button
            className="mobile-close-button"
            onClick={() => setMobileMenuOpen(false)}
          >
            <X size={20} />
          </button>
        </div>

        <div className="sidebar-label">WORKSPACE</div>

        <nav className="sidebar-nav">
          <button
            className={`nav-item ${
              activePage === "overview" ? "active" : ""
            }`}
            onClick={() => navigate("overview")}
          >
            <LayoutDashboard size={19} />
            <span>Overview</span>
          </button>

          <button
            className={`nav-item ${
              activePage === "new-scan" ? "active" : ""
            }`}
            onClick={() => navigate("new-scan")}
          >
            <Upload size={19} />
            <span>New Scan</span>
          </button>

          <button
            className={`nav-item ${
              activePage === "version-comparison" ? "active" : ""
            }`}
            onClick={() => navigate("version-comparison")}
          >
            <RefreshCw size={19} />
            <span>Version Comparison</span>
            <span className="nav-stage-badge">03</span>
          </button>

          <button
            className={`nav-item ${
              activePage === "sandbox" ? "active" : ""
            }`}
            onClick={() => navigate("sandbox")}
          >
            <Radar size={19} />
            <span>Fake-Bait Sandbox</span>
            <span className="nav-stage-badge">04</span>
          </button>

          <button
            className={`nav-item ${
              activePage === "history" ? "active" : ""
            }`}
            onClick={() => navigate("history")}
          >
            <Clock3 size={19} />
            <span>Scan History</span>
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-security-card">
            <div className="security-card-icon">
              <ShieldCheck size={19} />
            </div>

            <div>
              <strong>Security Engine</strong>
              <span>Static analysis enabled</span>
            </div>
          </div>

          <div className="sidebar-version">
            <span>KodKavach</span>
            <span>Version 0.5.0</span>
          </div>
        </div>
      </aside>

      {/* Main application */}
      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu-button"
              onClick={() => setMobileMenuOpen(true)}
            >
              <Menu size={21} />
            </button>

            <div className="breadcrumb">
              <span>Workspace</span>
              <ChevronRight size={15} />
              <strong>
                {activePage === "overview"
                  ? "Overview"
                  : activePage === "new-scan"
                    ? "New Scan"
                    : activePage === "version-comparison"
                      ? "Version Comparison"
                      : activePage === "sandbox"
                        ? "Fake-Bait Sandbox"
                        : "Scan History"}
              </strong>
            </div>
          </div>

          <div className="topbar-right">
            <div
              className={`backend-indicator ${
                backendOnline ? "online" : "offline"
              }`}
            >
              <span className="status-dot" />
              <span>
                Backend {backendOnline ? "Connected" : "Offline"}
              </span>
            </div>

            <div className="topbar-icon">
              <Bell size={19} />
            </div>
          </div>
        </header>

        {/* Page content */}
        <div className="page-content">
          {/* OVERVIEW */}
          {activePage === "overview" && (
            <>
              <section className="welcome-section">
                <div>
                  <div className="eyebrow">
                    <Sparkles size={14} />
                    SOFTWARE SUPPLY CHAIN SECURITY
                  </div>

                  <h1>
                    Protect your <span>software supply chain.</span>
                  </h1>

                  <p>
                    Detect suspicious packages, investigate risky code
                    behaviour, and identify unexpected changes between
                    software versions.
                  </p>
                </div>

                <button
                  className="primary-button"
                  onClick={() => navigate("new-scan")}
                >
                  <Upload size={17} />
                  Start New Scan
                </button>
              </section>

              <section className="overview-stats">
                <div className="overview-stat">
                  <div className="overview-stat-icon">
                    <FileSearch size={20} />
                  </div>
                  <div>
                    <span>Packages Scanned</span>
                    <strong>
                      {scanHistory.length}
                    </strong>
                  </div>
                </div>

                <div className="overview-stat">
                  <div className="overview-stat-icon">
                    <AlertTriangle size={20} />
                  </div>
                  <div>
                    <span>Current Findings</span>
                    <strong>{findings.length}</strong>
                  </div>
                </div>

                <div className="overview-stat">
                  <div className="overview-stat-icon">
                    <ShieldCheck size={20} />
                  </div>
                  <div>
                    <span>Detection Stages</span>
                    <strong>{completedStages.length}/6</strong>
                  </div>
                </div>

                <div className="overview-stat">
                  <div className="overview-stat-icon">
                    <Activity size={20} />
                  </div>
                  <div>
                    <span>Backend Status</span>
                    <strong
                      className={
                        backendOnline ? "online-text" : "offline-text"
                      }
                    >
                      {backendOnline ? "Online" : "Offline"}
                    </strong>
                  </div>
                </div>
              </section>
              <ImplementationRoadmap />

              <section className="overview-main-grid">
                <div className="overview-primary">
                  {result ? (
                    renderResults()
                  ) : (
                    <div className="welcome-scan-card">
                      <div className="welcome-scan-icon">
                        <ShieldCheck size={35} />
                      </div>

                      <h2>Start securing your packages</h2>

                      <p>
                        Upload a Python package archive to inspect its
                        code for suspicious operations, credential
                        exposure, network activity, and other potentially
                        risky behaviours.
                      </p>

                      <button
                        className="primary-button"
                        onClick={() => navigate("new-scan")}
                      >
                        <Upload size={17} />
                        Upload Package
                      </button>
                    </div>
                  )}
                </div>

                <div className="overview-secondary">
                  <div className="pipeline-card">
                    <div className="section-heading">
                      <div>
                        <h3>Detection Pipeline</h3>
                        <p>Six planned security stages</p>
                      </div>
                      <Radar size={20} />
                    </div>

                    <div className="pipeline-list">
                      {STAGES.map((stage) => (
                        <div
                          className="pipeline-item"
                          key={stage.key}
                        >
                          <div className="pipeline-item-icon">
                            {completedStages.includes(stage.key) ? (
                              <CheckCircle2 size={17} />
                            ) : (
                              <Clock3 size={17} />
                            )}
                          </div>

                          <div className="pipeline-item-text">
                            <strong>{stage.name}</strong>
                            <span>{stage.description}</span>
                          </div>

                          <span
                            className={`pipeline-status ${
                              completedStages.includes(stage.key)
                                ? "completed"
                                : "pending"
                            }`}
                          >
                            {completedStages.includes(stage.key)
                              ? "Ready"
                              : "Set to Go"}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="quick-action-card">
                    <div className="quick-action-icon">
                      <RefreshCw size={21} />
                    </div>

                    <h3>Compare Package Versions</h3>

                    <p>
                      Detect new or removed behaviours between two
                      versions of a Python package.
                    </p>

                    <button
                      className="text-button"
                      onClick={() => navigate("version-comparison")}
                    >
                      Compare versions
                      <ArrowUpRight size={16} />
                    </button>
                  </div>

                  <div className="quick-action-card">
                    <div className="quick-action-icon">
                      <Radar size={21} />
                    </div>

                    <h3>Runtime Sandbox</h3>

                    <p>
                      Execute a package in an isolated Docker worker
                      and inspect its runtime behaviour.
                    </p>

                    <button
                      className="text-button"
                      onClick={() => navigate("sandbox")}
                    >
                      Open Sandbox
                      <ArrowUpRight size={16} />
                    </button>
                  </div>
                </div>
              </section>
            </>
          )}

          {/* NEW STATIC SCAN */}
          {activePage === "new-scan" && (
            <section className="page-section">
              <div className="page-title-section">
                <div className="eyebrow">PACKAGE ANALYSIS</div>
                <h1>New Security Scan</h1>
                <p>
                  Upload a Python package archive and analyze its
                  contents for potentially malicious behaviour.
                </p>
              </div>

              {renderUploadPanel()}

              {result && (
                <div className="page-results">
                  {renderResults()}
                </div>
              )}
            </section>
          )}

          {/* VERSION COMPARISON */}
          {activePage === "version-comparison" && (
            <section className="page-section">
              <div className="page-title-section">
                <div className="eyebrow">
                  STAGE 3 · UPDATE HIJACK DETECTOR
                </div>
                <h1>Version Comparison</h1>
                <p>
                  Compare two versions of a Python package to identify
                  unexpected changes in code behaviour.
                </p>
              </div>

              <div className="comparison-upload-panel">
                <div className="section-heading">
                  <div>
                    <h2>Compare Package Versions</h2>
                    <p>
                      Provide the original and updated package archives.
                    </p>
                  </div>
                  <RefreshCw size={22} />
                </div>

                <div className="comparison-upload-grid">
                  <div className="version-upload-field">
                    <label htmlFor="baseline-version">
                      Baseline Version
                    </label>

                    <input
                      id="baseline-version"
                      type="text"
                      placeholder="e.g. 1.0.0"
                      value={baselineVersion}
                      onChange={(event) =>
                        setBaselineVersion(event.target.value)
                      }
                    />

                    <label htmlFor="baseline-file">
                      Original Package Archive
                    </label>

                    <input
                      id="baseline-file"
                      type="file"
                      accept=".zip,.tar,.gz,.tgz,.whl"
                      onChange={(event) =>
                        setBaselineFile(
                          event.target.files?.[0] || null
                        )
                      }
                    />

                    {baselineFile && (
                      <div className="selected-file-name">
                        <FileArchive size={15} />
                        {baselineFile.name}
                      </div>
                    )}
                  </div>

                  <div className="version-upload-field">
                    <label htmlFor="candidate-version">
                      Candidate Version
                    </label>

                    <input
                      id="candidate-version"
                      type="text"
                      placeholder="e.g. 1.1.0"
                      value={candidateVersion}
                      onChange={(event) =>
                        setCandidateVersion(event.target.value)
                      }
                    />

                    <label htmlFor="candidate-file">
                      Updated Package Archive
                    </label>

                    <input
                      id="candidate-file"
                      type="file"
                      accept=".zip,.tar,.gz,.tgz,.whl"
                      onChange={(event) =>
                        setCandidateFile(
                          event.target.files?.[0] || null
                        )
                      }
                    />

                    {candidateFile && (
                      <div className="selected-file-name">
                        <FileArchive size={15} />
                        {candidateFile.name}
                      </div>
                    )}
                  </div>
                </div>

                {comparisonError && (
                  <div className="error-message">
                    <AlertTriangle size={17} />
                    <span>{comparisonError}</span>
                  </div>
                )}

                <div className="comparison-upload-actions">
                  <button
                    className="primary-button"
                    onClick={startVersionComparison}
                    disabled={
                      comparing ||
                      !baselineFile ||
                      !candidateFile ||
                      !baselineVersion.trim() ||
                      !candidateVersion.trim()
                    }
                  >
                    {comparing ? (
                      <>
                        <LoaderCircle size={17} className="spin" />
                        Comparing Versions...
                      </>
                    ) : (
                      <>
                        <RefreshCw size={17} />
                        Compare Versions
                      </>
                    )}
                  </button>
                </div>

                <div className="upload-note">
                  <LockKeyhole size={15} />
                  <span>
                    Both archives are statically analyzed. Their
                    package code is not executed during this comparison.
                  </span>
                </div>
              </div>

              {comparisonResult && (
                <div className="page-results">
                  {renderVersionComparison()}
                </div>
              )}
            </section>
          )}

          {/* STAGE 4: FAKE-BAIT SANDBOX */}
          {activePage === "sandbox" && (
            <section className="page-section">
              <div className="page-title-section">
                <div className="eyebrow">
                  STAGE 4 · FAKE-BAIT SANDBOX
                </div>
                <h1>Runtime Behaviour Analysis</h1>
                <p>
                  Execute a Python package entrypoint inside the
                  isolated Docker worker and inspect the runtime
                  evidence it records.
                </p>
              </div>

              <div className="sandbox-upload-panel">
                <div className="section-heading">
                  <div>
                    <h2>Run Package in Sandbox</h2>
                    <p>
                      Upload a Python archive and identify its
                      execution entrypoint.
                    </p>
                  </div>
                  <Radar size={22} />
                </div>

                <div className="sandbox-form-grid">
                  <div className="sandbox-field sandbox-file-field">
                    <label htmlFor="sandbox-package">
                      Python package archive
                    </label>

                    <input
                      id="sandbox-package"
                      type="file"
                      accept=".zip,.tar,.gz,.tgz,.whl"
                      onChange={(event) => {
                        const file =
                          event.target.files?.[0] || null;

                        const allowed = [
                          ".zip",
                          ".tar.gz",
                          ".tgz",
                          ".whl",
                        ];

                        const valid =
                          file &&
                          allowed.some((extension) =>
                            file.name
                              .toLowerCase()
                              .endsWith(extension)
                          );

                        if (file && !valid) {
                          setSandboxFile(null);
                          setSandboxError(
                            "Unsupported archive. Use .zip, .tar.gz, .tgz or .whl."
                          );
                          return;
                        }

                        if (file && file.size > 50 * 1024 * 1024) {
                          setSandboxFile(null);
                          setSandboxError(
                            "File exceeds the 50 MB upload limit."
                          );
                          return;
                        }

                        setSandboxFile(file);
                        setSandboxError("");
                        setSandboxResult(null);
                      }}
                    />

                    <span className="sandbox-field-help">
                      Supported: .zip, .tar.gz, .tgz and .whl ·
                      Maximum 50 MB
                    </span>

                    {sandboxFile && (
                      <div className="selected-file-name">
                        <FileArchive size={15} />
                        {sandboxFile.name}
                        <span>
                          (
                          {(
                            sandboxFile.size /
                            (1024 * 1024)
                          ).toFixed(2)}{" "}
                          MB)
                        </span>
                      </div>
                    )}
                  </div>

                  <div className="sandbox-field">
                    <label htmlFor="sandbox-entrypoint">
                      Python entrypoint
                    </label>

                    <input
                      id="sandbox-entrypoint"
                      type="text"
                      value={sandboxEntrypoint}
                      placeholder="e.g. package_name/__main__.py"
                      onChange={(event) =>
                        setSandboxEntrypoint(event.target.value)
                      }
                    />

                    <span className="sandbox-field-help">
                      Path relative to the extracted package root.
                    </span>
                  </div>
                </div>

                {sandboxError && (
                  <div className="error-message">
                    <AlertTriangle size={17} />
                    <span>{sandboxError}</span>
                  </div>
                )}

                <div className="sandbox-upload-actions">
                  <button
                    className="primary-button"
                    onClick={startSandbox}
                    disabled={
                      !sandboxFile ||
                      sandboxRunning ||
                      !backendOnline
                    }
                  >
                    {sandboxRunning ? (
                      <>
                        <LoaderCircle
                          size={17}
                          className="spin"
                        />
                        Running in Sandbox...
                      </>
                    ) : (
                      <>
                        <ShieldCheck size={17} />
                        Execute in Isolated Sandbox
                      </>
                    )}
                  </button>

                  {sandboxFile && (
                    <button
                      className="secondary-button"
                      disabled={sandboxRunning}
                      onClick={() => {
                        setSandboxFile(null);
                        setSandboxError("");
                        setSandboxResult(null);

                        const input = document.getElementById(
                          "sandbox-package"
                        );

                        if (input) {
                          input.value = "";
                        }
                      }}
                    >
                      <X size={16} />
                      Remove File
                    </button>
                  )}
                </div>

                <div className="upload-note">
                  <LockKeyhole size={15} />
                  <span>
                    Runs in the configured Docker worker with network
                    access disabled and restricted container privileges.
                    Runtime monitoring uses the worker's Python-level
                    event collection and is not a guarantee of complete
                    malware detection.
                  </span>
                </div>

                {!backendOnline && (
                  <p className="backend-hint">
                    Backend is offline. Start FastAPI before running
                    the sandbox.
                  </p>
                )}
              </div>

              {sandboxResult && (
                <div className="page-results">
                  {renderSandboxResults()}
                </div>
              )}
            </section>
          )}

          {/* SCAN HISTORY */}
          {activePage === "history" && (
            <section className="page-section">
              <div className="page-title-section">
                <div className="eyebrow">ACTIVITY</div>
                <h1>Scan History</h1>
                <p>
                  View the results of your previous package security scans.
                </p>
              </div>

              {renderHistory()}
            </section>
          )}
        </div>

        <footer className="app-footer">
          <div>
            <Shield size={15} />
            <span>KodKavach</span>
          </div>
          <span>
            Software Supply Chain Security Platform · v0.5.0
          </span>
        </footer>
      </main>
    </div>
  );
}

export default App;

