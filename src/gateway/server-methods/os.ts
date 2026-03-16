import { loadConfig, writeConfigFile } from "../../config/config.js";
import {
  createLocalOsApp,
  installLocalOsApp,
  listLocalOsApps,
  uninstallLocalOsApp,
} from "../../os/apps.js";
import { collectOsAttestation } from "../../os/attestation.js";
import { applyOpenClawOsDefaults, enforceOpenClawOsSecurityBaseline } from "../../os/policy.js";
import { buildStrictAuditReport } from "../../os/security-strict.js";
import { runSecurityAudit } from "../../security/audit.js";
import { ErrorCodes, errorShape } from "../protocol/index.js";
import type { GatewayRequestHandlers } from "./types.js";

function asTrimmedString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

export const osHandlers: GatewayRequestHandlers = {
  "os.attest": async ({ respond }) => {
    try {
      const report = await collectOsAttestation();
      respond(true, report, undefined);
    } catch (err) {
      respond(false, undefined, errorShape(ErrorCodes.UNAVAILABLE, String(err)));
    }
  },
  "os.security.status": async ({ respond }) => {
    try {
      const cfg = applyOpenClawOsDefaults(loadConfig());
      const report = await runSecurityAudit({
        config: cfg,
        sourceConfig: cfg,
        includeFilesystem: true,
        includeChannelSecurity: true,
        deep: false,
      });
      const strict = buildStrictAuditReport(report, cfg);
      respond(
        true,
        {
          strict: {
            passed: strict.passed,
            summary: strict.mergedSummary,
            findings: strict.strictFindings,
          },
          report: {
            ...report,
            summary: strict.mergedSummary,
            findings: strict.mergedFindings,
          },
        },
        undefined,
      );
    } catch (err) {
      respond(false, undefined, errorShape(ErrorCodes.UNAVAILABLE, String(err)));
    }
  },
  "os.security.enforce": async ({ respond }) => {
    try {
      const cfg = loadConfig();
      const result = enforceOpenClawOsSecurityBaseline(cfg);
      if (result.changes.length > 0) {
        await writeConfigFile(result.config);
      }
      respond(
        true,
        {
          changed: result.changes.length > 0,
          changes: result.changes,
          generatedGatewayToken: result.generatedGatewayToken,
        },
        undefined,
      );
    } catch (err) {
      respond(false, undefined, errorShape(ErrorCodes.UNAVAILABLE, String(err)));
    }
  },
  "os.apps.list": ({ respond }) => {
    try {
      respond(true, { apps: listLocalOsApps() }, undefined);
    } catch (err) {
      respond(false, undefined, errorShape(ErrorCodes.UNAVAILABLE, String(err)));
    }
  },
  "os.apps.create": ({ params, respond }) => {
    const name = asTrimmedString(params.name);
    const kindRaw = asTrimmedString(params.type);
    const description = asTrimmedString(params.description);
    if (!name) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "name is required"));
      return;
    }
    const kind = kindRaw === "from-scratch" ? "from-scratch" : "simple";
    try {
      const created = createLocalOsApp({
        config: applyOpenClawOsDefaults(loadConfig()),
        name,
        kind,
        description: description || undefined,
      });
      respond(true, created, undefined);
    } catch (err) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, String(err)));
    }
  },
  "os.apps.install": ({ params, respond }) => {
    const appId = asTrimmedString(params.appId);
    if (!appId) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "appId is required"));
      return;
    }
    try {
      const installed = installLocalOsApp({ appId });
      respond(true, installed, undefined);
    } catch (err) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, String(err)));
    }
  },
  "os.apps.uninstall": ({ params, respond }) => {
    const appId = asTrimmedString(params.appId);
    if (!appId) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "appId is required"));
      return;
    }
    try {
      const uninstalled = uninstallLocalOsApp({
        appId,
        purge: asBoolean(params.purge) ?? false,
      });
      respond(true, uninstalled, undefined);
    } catch (err) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, String(err)));
    }
  },
};
