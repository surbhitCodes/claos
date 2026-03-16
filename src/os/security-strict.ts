import type { OpenClawConfig } from "../config/config.js";
import type {
  SecurityAuditFinding,
  SecurityAuditReport,
  SecurityAuditSummary,
} from "../security/audit.js";
import { OPENCLAW_OS_DEFAULTS } from "./policy.js";

export type OsStrictSecurityReport = {
  report: SecurityAuditReport;
  strictFindings: SecurityAuditFinding[];
  mergedFindings: SecurityAuditFinding[];
  mergedSummary: SecurityAuditSummary;
  passed: boolean;
};

function countBySeverity(findings: SecurityAuditFinding[]): SecurityAuditSummary {
  let critical = 0;
  let warn = 0;
  let info = 0;
  for (const finding of findings) {
    if (finding.severity === "critical") {
      critical += 1;
      continue;
    }
    if (finding.severity === "warn") {
      warn += 1;
      continue;
    }
    info += 1;
  }
  return { critical, warn, info };
}

function maybePush(
  findings: SecurityAuditFinding[],
  condition: boolean,
  finding: SecurityAuditFinding,
): void {
  if (condition) {
    findings.push(finding);
  }
}

export function collectStrictPolicyFindings(cfg: OpenClawConfig): SecurityAuditFinding[] {
  const findings: SecurityAuditFinding[] = [];

  maybePush(findings, cfg.system?.os?.security?.profile !== OPENCLAW_OS_DEFAULTS.securityProfile, {
    checkId: "os.strict.system.profile",
    severity: "critical",
    title: "OpenClaw OS security profile is not strict",
    detail: `Expected system.os.security.profile=${OPENCLAW_OS_DEFAULTS.securityProfile}.`,
    remediation: "Set `system.os.security.profile` to `strict`.",
  });

  maybePush(findings, cfg.system?.os?.boot?.integrity !== OPENCLAW_OS_DEFAULTS.bootIntegrity, {
    checkId: "os.strict.system.boot_integrity",
    severity: "critical",
    title: "OpenClaw OS boot integrity policy is not required",
    detail: `Expected system.os.boot.integrity=${OPENCLAW_OS_DEFAULTS.bootIntegrity}.`,
    remediation: "Set `system.os.boot.integrity` to `required`.",
  });

  maybePush(findings, cfg.system?.os?.runtime?.sandbox !== OPENCLAW_OS_DEFAULTS.runtimeSandbox, {
    checkId: "os.strict.system.runtime_sandbox",
    severity: "critical",
    title: "OpenClaw OS runtime sandbox policy is not required",
    detail: `Expected system.os.runtime.sandbox=${OPENCLAW_OS_DEFAULTS.runtimeSandbox}.`,
    remediation: "Set `system.os.runtime.sandbox` to `required`.",
  });

  maybePush(
    findings,
    cfg.system?.os?.privacy?.inferenceRouting !== OPENCLAW_OS_DEFAULTS.inferenceRouting,
    {
      checkId: "os.strict.system.inference_routing",
      severity: "critical",
      title: "OpenClaw OS inference routing policy is not hybrid-classified",
      detail: `Expected system.os.privacy.inferenceRouting=${OPENCLAW_OS_DEFAULTS.inferenceRouting}.`,
      remediation: "Set `system.os.privacy.inferenceRouting` to `hybrid-classified`.",
    },
  );

  maybePush(
    findings,
    cfg.system?.os?.telemetry?.enabled !== OPENCLAW_OS_DEFAULTS.telemetryEnabled,
    {
      checkId: "os.strict.system.telemetry_opt_in",
      severity: "critical",
      title: "OpenClaw OS telemetry is not opt-in",
      detail: "Expected system.os.telemetry.enabled=false under strict baseline.",
      remediation: "Set `system.os.telemetry.enabled` to `false`.",
    },
  );

  maybePush(findings, (cfg.gateway?.bind ?? "loopback") !== "loopback", {
    checkId: "os.strict.gateway.bind",
    severity: "critical",
    title: "Gateway is not loopback-bound",
    detail: "Strict OpenClaw OS baseline requires gateway.bind=loopback.",
    remediation: "Set `gateway.bind` to `loopback`.",
  });

  const authMode = cfg.gateway?.auth?.mode;
  maybePush(findings, authMode == null || authMode === "none", {
    checkId: "os.strict.gateway.auth_mode",
    severity: "critical",
    title: "Gateway auth mode is not hardened",
    detail: "Strict OpenClaw OS baseline requires gateway auth mode token/password/trusted-proxy.",
    remediation: "Set `gateway.auth.mode` to `token` (recommended for local appliance mode).",
  });

  maybePush(findings, cfg.tools?.exec?.host !== "sandbox", {
    checkId: "os.strict.tools.exec_host",
    severity: "critical",
    title: "Exec host is not sandbox",
    detail: "Strict OpenClaw OS baseline requires tools.exec.host=sandbox.",
    remediation: "Set `tools.exec.host` to `sandbox`.",
  });

  maybePush(findings, cfg.tools?.exec?.security !== "full", {
    checkId: "os.strict.tools.exec_security",
    severity: "critical",
    title: "Exec security is not autonomous-full",
    detail:
      "Strict OpenClaw OS baseline for autonomous builders requires tools.exec.security=full in sandbox mode.",
    remediation: "Set `tools.exec.security` to `full` while keeping `tools.exec.host=sandbox`.",
  });

  maybePush(findings, cfg.tools?.exec?.ask !== "off", {
    checkId: "os.strict.tools.exec_ask",
    severity: "critical",
    title: "Exec ask mode is not autonomous",
    detail: "Strict OpenClaw OS autonomous baseline requires tools.exec.ask=off.",
    remediation: "Set `tools.exec.ask` to `off` for autonomous sandboxed operation.",
  });

  maybePush(findings, cfg.tools?.elevated?.enabled === true, {
    checkId: "os.strict.tools.elevated_enabled",
    severity: "critical",
    title: "Elevated tools are enabled",
    detail: "Strict OpenClaw OS baseline requires tools.elevated.enabled=false.",
    remediation: "Set `tools.elevated.enabled` to `false`.",
  });

  maybePush(
    findings,
    cfg.agents?.defaults?.sandbox?.mode === "off" || cfg.agents?.defaults?.sandbox?.mode == null,
    {
      checkId: "os.strict.agents.sandbox_mode",
      severity: "critical",
      title: "Agent sandbox mode is not enforced",
      detail: "Strict OpenClaw OS baseline requires agents.defaults.sandbox.mode to be non-off.",
      remediation: "Set `agents.defaults.sandbox.mode` to `all` (or `non-main` as fallback).",
    },
  );

  maybePush(findings, cfg.tools?.profile !== "coding", {
    checkId: "os.strict.tools.profile",
    severity: "critical",
    title: "Tool profile is not coding",
    detail: "Strict OpenClaw OS autonomous baseline expects tools.profile=coding.",
    remediation: "Set `tools.profile` to `coding`.",
  });

  maybePush(
    findings,
    (typeof cfg.agents?.defaults?.model === "string"
      ? cfg.agents.defaults.model
      : cfg.agents?.defaults?.model?.primary) !== OPENCLAW_OS_DEFAULTS.autonomyDefaultModel,
    {
      checkId: "os.strict.models.primary",
      severity: "critical",
      title: "Default autonomous model is not Ollama local default",
      detail: `Expected agents.defaults.model.primary=${OPENCLAW_OS_DEFAULTS.autonomyDefaultModel}.`,
      remediation: `Set \`agents.defaults.model.primary\` to \`${OPENCLAW_OS_DEFAULTS.autonomyDefaultModel}\`.`,
    },
  );

  maybePush(findings, cfg.models?.providers?.ollama?.api !== "ollama", {
    checkId: "os.strict.models.ollama_provider",
    severity: "critical",
    title: "Ollama provider API adapter is not configured",
    detail: "Strict OpenClaw OS autonomous baseline expects models.providers.ollama.api=ollama.",
    remediation: "Set `models.providers.ollama.api` to `ollama`.",
  });

  maybePush(findings, cfg.system?.os?.autonomy?.enabled !== OPENCLAW_OS_DEFAULTS.autonomyEnabled, {
    checkId: "os.strict.system.autonomy_enabled",
    severity: "critical",
    title: "Autonomy mode is disabled",
    detail: "Strict OpenClaw OS autonomous baseline expects system.os.autonomy.enabled=true.",
    remediation: "Set `system.os.autonomy.enabled` to `true`.",
  });

  maybePush(findings, cfg.system?.os?.apps?.autoInstall !== OPENCLAW_OS_DEFAULTS.appsAutoInstall, {
    checkId: "os.strict.system.apps_auto_install",
    severity: "warn",
    title: "Local app auto-install is disabled",
    detail: "CLAOS baseline expects newly generated local apps to auto-install.",
    remediation: "Set `system.os.apps.autoInstall` to `true`.",
  });

  maybePush(
    findings,
    cfg.system?.os?.apps?.fromScratch?.requireProviders !==
      OPENCLAW_OS_DEFAULTS.appsFromScratchRequireProviders,
    {
      checkId: "os.strict.system.apps_from_scratch_provider_requirements",
      severity: "critical",
      title: "From-scratch app generation provider requirement is relaxed",
      detail:
        "Strict baseline requires both Anthropic and OpenAI credentials for from-scratch apps.",
      remediation: "Set `system.os.apps.fromScratch.requireProviders` to `true`.",
    },
  );

  return findings;
}

export function buildStrictAuditReport(
  report: SecurityAuditReport,
  cfg: OpenClawConfig,
): OsStrictSecurityReport {
  const strictFindings = collectStrictPolicyFindings(cfg);
  const mergedFindings = [...report.findings, ...strictFindings];
  const mergedSummary = countBySeverity(mergedFindings);
  const passed = mergedSummary.critical === 0 && mergedSummary.warn === 0;

  return {
    report,
    strictFindings,
    mergedFindings,
    mergedSummary,
    passed,
  };
}
