import { describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../config/config.js";
import {
  OPENCLAW_OS_DEFAULTS,
  applyOpenClawOsDefaults,
  enforceOpenClawOsSecurityBaseline,
} from "./policy.js";

describe("os policy", () => {
  it("applies OpenClaw OS default policy values", () => {
    const config: OpenClawConfig = {};
    const result = applyOpenClawOsDefaults(config);

    expect(result.system?.os?.security?.profile).toBe(OPENCLAW_OS_DEFAULTS.securityProfile);
    expect(result.system?.os?.boot?.integrity).toBe(OPENCLAW_OS_DEFAULTS.bootIntegrity);
    expect(result.system?.os?.runtime?.sandbox).toBe(OPENCLAW_OS_DEFAULTS.runtimeSandbox);
    expect(result.system?.os?.privacy?.inferenceRouting).toBe(
      OPENCLAW_OS_DEFAULTS.inferenceRouting,
    );
    expect(result.system?.os?.telemetry?.enabled).toBe(OPENCLAW_OS_DEFAULTS.telemetryEnabled);
    expect(result.system?.os?.autonomy?.enabled).toBe(OPENCLAW_OS_DEFAULTS.autonomyEnabled);
    expect(result.system?.os?.autonomy?.defaultModel).toBe(
      OPENCLAW_OS_DEFAULTS.autonomyDefaultModel,
    );
    expect(result.system?.os?.apps?.autoInstall).toBe(OPENCLAW_OS_DEFAULTS.appsAutoInstall);
    expect(result.system?.os?.apps?.simple?.model).toBe(OPENCLAW_OS_DEFAULTS.appsSimpleModel);
    expect(result.system?.os?.apps?.fromScratch?.requireProviders).toBe(
      OPENCLAW_OS_DEFAULTS.appsFromScratchRequireProviders,
    );
  });

  it("enforces hardened baseline config", () => {
    const source: OpenClawConfig = {
      gateway: {
        bind: "lan",
        auth: { mode: "none" },
      },
      tools: {
        exec: { host: "node", security: "full", ask: "off" },
        elevated: { enabled: true },
      },
      agents: {
        defaults: {
          sandbox: { mode: "off" },
        },
      },
    };

    const result = enforceOpenClawOsSecurityBaseline(source);

    expect(result.changes.length).toBeGreaterThan(0);
    expect(result.config.gateway?.bind).toBe("loopback");
    expect(result.config.gateway?.auth?.mode).toBe("token");
    expect(result.config.tools?.exec?.host).toBe("sandbox");
    expect(result.config.tools?.exec?.security).toBe("full");
    expect(result.config.tools?.exec?.ask).toBe("off");
    expect(result.config.tools?.elevated?.enabled).toBe(false);
    expect(result.config.tools?.profile).toBe("coding");
    expect(result.config.agents?.defaults?.sandbox?.mode).toBe("all");
    expect(
      typeof result.config.agents?.defaults?.model === "string"
        ? result.config.agents?.defaults?.model
        : result.config.agents?.defaults?.model?.primary,
    ).toBe(OPENCLAW_OS_DEFAULTS.autonomyDefaultModel);
    expect(result.config.models?.providers?.ollama?.api).toBe("ollama");
    expect(result.config.models?.providers?.ollama?.baseUrl).toBe("http://127.0.0.1:11434");
    expect(result.config.system?.os?.autonomy?.enabled).toBe(true);
    expect(result.config.system?.os?.apps?.autoInstall).toBe(true);
    expect(typeof result.config.gateway?.auth?.token).toBe("string");
    expect(result.generatedGatewayToken).toBe(true);
  });
});
