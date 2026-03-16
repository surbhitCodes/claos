import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { loadConfig, writeConfigFile } from "../config/config.js";
import { resolveOpenClawPackageRootSync } from "../infra/openclaw-root.js";
import {
  createLocalOsApp,
  installLocalOsApp,
  listLocalOsApps,
  uninstallLocalOsApp,
  type OsAppKind,
} from "../os/apps.js";
import { collectOsAttestation, type OsAttestationReport } from "../os/attestation.js";
import {
  applyOpenClawOsDefaults,
  enforceOpenClawOsSecurityBaseline,
  summarizeOsPolicy,
} from "../os/policy.js";
import { buildStrictAuditReport } from "../os/security-strict.js";
import { runCommandWithTimeout } from "../process/exec.js";
import { defaultRuntime } from "../runtime.js";
import { runSecurityAudit } from "../security/audit.js";
import { formatDocsLink } from "../terminal/links.js";
import { isRich, theme } from "../terminal/theme.js";
import { runCommandWithRuntime } from "./cli-utils.js";
import { formatCliCommand } from "./command-format.js";
import { formatHelpExamples } from "./help-format.js";

type OsAttestOptions = { json?: boolean };

type OsSecurityStatusOptions = { json?: boolean; deep?: boolean };

type OsSecurityEnforceOptions = { json?: boolean };

type OsActionOptions = { json?: boolean; yes?: boolean; timeoutMs?: string };
type OsAppCreateOptions = { type?: OsAppKind; description?: string; json?: boolean };
type OsAppListOptions = { json?: boolean };
type OsAppInstallOptions = { json?: boolean };
type OsAppUninstallOptions = { json?: boolean; purge?: boolean; yes?: boolean };

function runOsCommand(action: () => Promise<void>) {
  return runCommandWithRuntime(defaultRuntime, action, (err) => {
    defaultRuntime.error(String(err));
    defaultRuntime.exit(1);
  });
}

function formatSecuritySummary(summary: { critical: number; warn: number; info: number }): string {
  const rich = isRich();
  const parts: string[] = [];
  parts.push(rich ? theme.error(`${summary.critical} critical`) : `${summary.critical} critical`);
  parts.push(rich ? theme.warn(`${summary.warn} warn`) : `${summary.warn} warn`);
  parts.push(rich ? theme.muted(`${summary.info} info`) : `${summary.info} info`);
  return parts.join(" · ");
}

function resolveBundledScript(relativePath: string): string {
  const packageRoot =
    resolveOpenClawPackageRootSync({
      cwd: process.cwd(),
      moduleUrl: import.meta.url,
    }) ?? process.cwd();
  return path.resolve(packageRoot, relativePath);
}

async function runOsScript(params: { scriptPath: string; timeoutMs: number }): Promise<{
  ok: boolean;
  code: number;
  stdout: string;
  stderr: string;
}> {
  const result = await runCommandWithTimeout([params.scriptPath], { timeoutMs: params.timeoutMs });
  return {
    ok: result.code === 0,
    code: result.code ?? 1,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function renderAttestation(report: OsAttestationReport): string {
  const rich = isRich();
  const heading = (value: string) => (rich ? theme.heading(value) : value);

  const lines: string[] = [];
  lines.push(heading("OpenClaw OS attestation"));
  lines.push(
    `Summary: ${report.summary.pass} pass · ${report.summary.fail} fail · ${report.summary.unknown} unknown`,
  );

  for (const check of report.checks) {
    const status =
      check.status === "pass"
        ? rich
          ? theme.success("PASS")
          : "PASS"
        : check.status === "fail"
          ? rich
            ? theme.error("FAIL")
            : "FAIL"
          : rich
            ? theme.warn("UNKNOWN")
            : "UNKNOWN";
    const required = check.required ? "required" : "advisory";
    lines.push(`- [${status}] ${check.title} (${required})`);
    lines.push(`  ${check.detail}`);
  }

  return lines.join("\n");
}

export function registerOsCli(program: Command) {
  const os = program
    .command("os")
    .description("OpenClaw OS hardening, attestation, and recovery controls")
    .addHelpText(
      "after",
      () =>
        `\n${theme.heading("Examples:")}\n${formatHelpExamples([
          ["openclaw os attest", "Run host-level OpenClaw OS attestation checks."],
          ["openclaw os security status", "Run strict OpenClaw OS security status checks."],
          [
            "openclaw os security enforce",
            "Apply hardened OpenClaw OS defaults to local config and re-audit.",
          ],
          [
            'openclaw config set models.providers.openai.apiKey "$OPENAI_API_KEY"',
            "Optionally add cloud model APIs while keeping Ollama as default.",
          ],
          ["openclaw os rollback --yes", "Run the configured OpenClaw OS rollback action."],
          ["openclaw os recovery --yes", "Run the configured OpenClaw OS recovery action."],
          [
            "openclaw os app create notes --type simple",
            "Create metadata-first local app scaffold.",
          ],
          [
            "openclaw os app create builder --type from-scratch",
            "Create from-scratch local app scaffold (requires Anthropic + OpenAI credentials).",
          ],
          ["openclaw os app uninstall notes --yes", "Uninstall a local app (optional --purge)."],
        ])}\n\n${theme.muted("Docs:")} ${formatDocsLink(
          "/gateway/security",
          "docs.openclaw.ai/gateway/security",
        )}\n`,
    );

  os.command("attest")
    .description("Run OpenClaw OS boot/runtime attestation checks")
    .option("--json", "Output JSON", false)
    .action(async (opts: OsAttestOptions) => {
      await runOsCommand(async () => {
        const report = await collectOsAttestation();
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(report, null, 2));
        } else {
          defaultRuntime.log(renderAttestation(report));
        }
        if (report.summary.fail > 0) {
          defaultRuntime.exit(1);
        }
      });
    });

  const security = os.command("security").description("OpenClaw OS strict security controls");

  security
    .command("status")
    .description("Run strict OpenClaw OS security status checks")
    .option("--deep", "Include best-effort live gateway probe checks", false)
    .option("--json", "Output JSON", false)
    .action(async (opts: OsSecurityStatusOptions) => {
      await runOsCommand(async () => {
        const cfg = applyOpenClawOsDefaults(loadConfig());
        const report = await runSecurityAudit({
          config: cfg,
          sourceConfig: cfg,
          deep: Boolean(opts.deep),
          includeFilesystem: true,
          includeChannelSecurity: true,
        });
        const strict = buildStrictAuditReport(report, cfg);

        if (opts.json) {
          defaultRuntime.log(
            JSON.stringify(
              {
                strict: {
                  passed: strict.passed,
                  summary: strict.mergedSummary,
                  strictFindings: strict.strictFindings,
                },
                report: {
                  ...report,
                  summary: strict.mergedSummary,
                  findings: strict.mergedFindings,
                },
                policy: summarizeOsPolicy(cfg),
              },
              null,
              2,
            ),
          );
        } else {
          const lines: string[] = [];
          lines.push(theme.heading("OpenClaw OS strict security status"));
          lines.push(theme.muted(`Summary: ${formatSecuritySummary(strict.mergedSummary)}`));
          lines.push(
            theme.muted(`Base audit: ${formatCliCommand("openclaw security audit --strict")}`),
          );
          lines.push(theme.muted(`Policy: ${JSON.stringify(summarizeOsPolicy(cfg))}`));

          if (strict.strictFindings.length > 0) {
            lines.push("");
            lines.push(theme.heading("STRICT POLICY FINDINGS"));
            for (const finding of strict.strictFindings) {
              lines.push(`${theme.muted(finding.checkId)} ${finding.title}`);
              lines.push(`  ${finding.detail}`);
              if (finding.remediation) {
                lines.push(`  ${theme.muted(`Fix: ${finding.remediation}`)}`);
              }
            }
          }

          defaultRuntime.log(lines.join("\n"));
        }

        if (!strict.passed) {
          defaultRuntime.exit(1);
        }
      });
    });

  security
    .command("enforce")
    .description("Apply hardened OpenClaw OS defaults and strict controls")
    .option("--json", "Output JSON", false)
    .action(async (opts: OsSecurityEnforceOptions) => {
      await runOsCommand(async () => {
        const source = loadConfig();
        const {
          config: next,
          changes,
          generatedGatewayToken,
        } = enforceOpenClawOsSecurityBaseline(source);

        if (changes.length > 0) {
          await writeConfigFile(next);
        }

        const audit = await runSecurityAudit({
          config: next,
          sourceConfig: next,
          includeFilesystem: true,
          includeChannelSecurity: true,
        });
        const strict = buildStrictAuditReport(audit, next);

        if (opts.json) {
          defaultRuntime.log(
            JSON.stringify(
              {
                changed: changes.length > 0,
                changes,
                generatedGatewayToken,
                strict: {
                  passed: strict.passed,
                  summary: strict.mergedSummary,
                },
                policy: summarizeOsPolicy(next),
              },
              null,
              2,
            ),
          );
        } else {
          const lines: string[] = [];
          lines.push(theme.heading("OpenClaw OS security enforce"));
          if (changes.length === 0) {
            lines.push(theme.muted("No config changes were required."));
          } else {
            lines.push(theme.muted("Applied changes:"));
            for (const change of changes) {
              lines.push(`  ${change}`);
            }
          }

          if (generatedGatewayToken) {
            lines.push(
              theme.warn(
                "Generated a new gateway token. Store it securely and rotate external clients if needed.",
              ),
            );
          }

          lines.push(theme.muted(`Strict summary: ${formatSecuritySummary(strict.mergedSummary)}`));
          lines.push(theme.muted(`Policy: ${JSON.stringify(summarizeOsPolicy(next))}`));
          lines.push(
            theme.muted(
              `Add optional cloud providers: ${formatCliCommand(
                'openclaw config set models.providers.<provider>.apiKey "$PROVIDER_API_KEY"',
              )}`,
            ),
          );
          defaultRuntime.log(lines.join("\n"));
        }

        if (!strict.passed) {
          defaultRuntime.exit(1);
        }
      });
    });

  const registerActionCommand = (
    name: "rollback" | "recovery",
    description: string,
    envKey: "OPENCLAW_OS_ROLLBACK_SCRIPT" | "OPENCLAW_OS_RECOVERY_SCRIPT",
    defaultScript: string,
  ) => {
    os.command(name)
      .description(description)
      .option("--yes", "Confirm action", false)
      .option("--timeout-ms <ms>", "Timeout in milliseconds", "120000")
      .option("--json", "Output JSON", false)
      .action(async (opts: OsActionOptions) => {
        await runOsCommand(async () => {
          if (!opts.yes) {
            throw new Error(`Pass --yes to execute ${name}.`);
          }

          const scriptPath = (process.env[envKey] || resolveBundledScript(defaultScript)).trim();
          if (!scriptPath) {
            throw new Error(`No ${name} script configured.`);
          }
          if (!fs.existsSync(scriptPath)) {
            throw new Error(`Script not found: ${scriptPath}`);
          }

          const timeoutMs = Number.parseInt(String(opts.timeoutMs ?? "120000"), 10);
          const result = await runOsScript({
            scriptPath,
            timeoutMs: Number.isFinite(timeoutMs) ? timeoutMs : 120_000,
          });

          if (opts.json) {
            defaultRuntime.log(
              JSON.stringify(
                {
                  action: name,
                  ok: result.ok,
                  code: result.code,
                  scriptPath,
                  stdout: result.stdout,
                  stderr: result.stderr,
                },
                null,
                2,
              ),
            );
          } else {
            defaultRuntime.log(theme.heading(`OpenClaw OS ${name}`));
            defaultRuntime.log(`Script: ${scriptPath}`);
            defaultRuntime.log(`Exit code: ${result.code}`);
            if (result.stdout.trim()) {
              defaultRuntime.log(result.stdout.trim());
            }
            if (result.stderr.trim()) {
              defaultRuntime.log(theme.warn(result.stderr.trim()));
            }
          }

          if (!result.ok) {
            defaultRuntime.exit(1);
          }
        });
      });
  };

  registerActionCommand(
    "rollback",
    "Restore last known-good OpenClaw OS slot",
    "OPENCLAW_OS_ROLLBACK_SCRIPT",
    "scripts/os/rollback.sh",
  );
  registerActionCommand(
    "recovery",
    "Run OpenClaw OS recovery workflow",
    "OPENCLAW_OS_RECOVERY_SCRIPT",
    "scripts/os/recovery.sh",
  );

  const app = os.command("app").description("Manage CLAOS local apps");

  app
    .command("create")
    .description("Create a local app and install it automatically by policy")
    .argument("<name>", "App name")
    .option("--type <type>", "App type: simple | from-scratch", "simple")
    .option("--description <text>", "Optional app description")
    .option("--json", "Output JSON", false)
    .action(async (name: string, opts: OsAppCreateOptions) => {
      await runOsCommand(async () => {
        const kind = opts.type === "from-scratch" ? "from-scratch" : "simple";
        const cfg = applyOpenClawOsDefaults(loadConfig());
        const created = createLocalOsApp({
          config: cfg,
          name,
          kind,
          description: opts.description,
        });
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(created, null, 2));
          return;
        }
        const lines = [
          theme.heading("OpenClaw OS app created"),
          `id: ${created.id}`,
          `name: ${created.name}`,
          `type: ${created.kind}`,
          `status: ${created.status}`,
          `path: ${created.path}`,
        ];
        defaultRuntime.log(lines.join("\n"));
      });
    });

  app
    .command("list")
    .description("List local apps and installation status")
    .option("--json", "Output JSON", false)
    .action(async (opts: OsAppListOptions) => {
      await runOsCommand(async () => {
        const apps = listLocalOsApps();
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(apps, null, 2));
          return;
        }
        if (apps.length === 0) {
          defaultRuntime.log(theme.muted("No local apps found."));
          return;
        }
        const lines = [theme.heading("OpenClaw OS local apps")];
        for (const item of apps) {
          lines.push(`- ${item.id} (${item.kind}) · ${item.status}`);
        }
        defaultRuntime.log(lines.join("\n"));
      });
    });

  app
    .command("install")
    .description("Install a local app")
    .argument("<app-id>", "App id")
    .option("--json", "Output JSON", false)
    .action(async (appId: string, opts: OsAppInstallOptions) => {
      await runOsCommand(async () => {
        const installed = installLocalOsApp({ appId });
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(installed, null, 2));
          return;
        }
        defaultRuntime.log(
          [
            theme.heading("OpenClaw OS app installed"),
            `id: ${installed.id}`,
            `status: ${installed.status}`,
          ].join("\n"),
        );
      });
    });

  app
    .command("uninstall")
    .description("Uninstall a local app")
    .argument("<app-id>", "App id")
    .option("--purge", "Delete local app files", false)
    .option("--yes", "Confirm uninstall", false)
    .option("--json", "Output JSON", false)
    .action(async (appId: string, opts: OsAppUninstallOptions) => {
      await runOsCommand(async () => {
        if (!opts.yes) {
          throw new Error("Pass --yes to uninstall.");
        }
        const uninstalled = uninstallLocalOsApp({ appId, purge: Boolean(opts.purge) });
        if (opts.json) {
          defaultRuntime.log(JSON.stringify(uninstalled, null, 2));
          return;
        }
        const lines = [
          theme.heading("OpenClaw OS app uninstalled"),
          `id: ${uninstalled.id}`,
          `status: ${uninstalled.status}`,
          opts.purge ? "files: purged" : "files: retained",
        ];
        defaultRuntime.log(lines.join("\n"));
      });
    });
}
