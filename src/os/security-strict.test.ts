import { describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../config/config.js";
import type { SecurityAuditReport } from "../security/audit.js";
import { buildStrictAuditReport, collectStrictPolicyFindings } from "./security-strict.js";

function emptyReport(): SecurityAuditReport {
  return {
    ts: 0,
    summary: { critical: 0, warn: 0, info: 0 },
    findings: [],
  };
}

describe("os strict security", () => {
  it("returns findings for missing strict baseline", () => {
    const findings = collectStrictPolicyFindings({});
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((item) => item.checkId === "os.strict.system.profile")).toBe(true);
  });

  it("passes when strict baseline and audit are clean", () => {
    const cfg: OpenClawConfig = {
      system: {
        os: {
          security: { profile: "strict" },
          boot: { integrity: "required" },
          runtime: { sandbox: "required" },
          privacy: { inferenceRouting: "hybrid-classified" },
          telemetry: { enabled: false },
          autonomy: { enabled: true, defaultModel: "ollama/qwen3:4b" },
          apps: {
            autoInstall: true,
            simple: { model: "ollama/qwen3:4b" },
            fromScratch: {
              requireProviders: true,
              anthropicModel: "anthropic/claude-sonnet-4-6",
              openaiModel: "openai/gpt-5.4",
            },
          },
        },
      },
      gateway: {
        bind: "loopback",
        auth: { mode: "token", token: "token" },
      },
      tools: {
        profile: "coding",
        exec: { host: "sandbox", security: "full", ask: "off" },
        elevated: { enabled: false },
      },
      models: {
        providers: {
          ollama: {
            api: "ollama",
            baseUrl: "http://127.0.0.1:11434",
            models: [],
          },
        },
      },
      agents: {
        defaults: {
          model: { primary: "ollama/qwen3:4b" },
          sandbox: { mode: "all" },
        },
      },
    };

    const strict = buildStrictAuditReport(emptyReport(), cfg);
    expect(strict.strictFindings).toEqual([]);
    expect(strict.passed).toBe(true);
    expect(strict.mergedSummary).toEqual({ critical: 0, warn: 0, info: 0 });
  });

  it("fails when base audit contains warning findings", () => {
    const cfg: OpenClawConfig = {
      system: {
        os: {
          security: { profile: "strict" },
          boot: { integrity: "required" },
          runtime: { sandbox: "required" },
          privacy: { inferenceRouting: "hybrid-classified" },
          telemetry: { enabled: false },
          autonomy: { enabled: true, defaultModel: "ollama/qwen3:4b" },
          apps: {
            autoInstall: true,
            simple: { model: "ollama/qwen3:4b" },
            fromScratch: {
              requireProviders: true,
              anthropicModel: "anthropic/claude-sonnet-4-6",
              openaiModel: "openai/gpt-5.4",
            },
          },
        },
      },
      gateway: {
        bind: "loopback",
        auth: { mode: "token", token: "token" },
      },
      tools: {
        profile: "coding",
        exec: { host: "sandbox", security: "full", ask: "off" },
        elevated: { enabled: false },
      },
      models: {
        providers: {
          ollama: {
            api: "ollama",
            baseUrl: "http://127.0.0.1:11434",
            models: [],
          },
        },
      },
      agents: {
        defaults: {
          model: { primary: "ollama/qwen3:4b" },
          sandbox: { mode: "all" },
        },
      },
    };

    const strict = buildStrictAuditReport(
      {
        ts: 0,
        summary: { critical: 0, warn: 1, info: 0 },
        findings: [
          {
            checkId: "gateway.probe_failed",
            severity: "warn",
            title: "Gateway probe failed",
            detail: "refused",
          },
        ],
      },
      cfg,
    );

    expect(strict.passed).toBe(false);
    expect(strict.mergedSummary.warn).toBe(1);
  });
});
