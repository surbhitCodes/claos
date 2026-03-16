import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../config/config.js";
import {
  createLocalOsApp,
  installLocalOsApp,
  listLocalOsApps,
  resolveLocalAppDir,
  uninstallLocalOsApp,
} from "./apps.js";

function makeTmpStateDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-os-apps-"));
}

function baseConfig(): OpenClawConfig {
  return {
    system: {
      os: {
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
  };
}

const cleanupDirs: string[] = [];

afterEach(() => {
  for (const dir of cleanupDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("os apps", () => {
  it("creates a simple app and auto-installs it", () => {
    const stateDir = makeTmpStateDir();
    cleanupDirs.push(stateDir);

    const app = createLocalOsApp({
      config: baseConfig(),
      name: "Daily Planner",
      kind: "simple",
      stateDir,
    });

    expect(app.id).toBe("daily-planner");
    expect(app.status).toBe("installed");
    expect(
      fs.existsSync(path.join(resolveLocalAppDir(app.id, stateDir), "openclaw.app.json")),
    ).toBe(true);
    expect(
      fs.existsSync(path.join(resolveLocalAppDir(app.id, stateDir), "app.template.json")),
    ).toBe(true);
  });

  it("requires Anthropic and OpenAI credentials for from-scratch mode", () => {
    const stateDir = makeTmpStateDir();
    cleanupDirs.push(stateDir);

    expect(() =>
      createLocalOsApp({
        config: baseConfig(),
        name: "Code Builder",
        kind: "from-scratch",
        stateDir,
      }),
    ).toThrow(/requires configured model API credentials/i);
  });

  it("creates from-scratch app when both providers are configured", () => {
    const stateDir = makeTmpStateDir();
    cleanupDirs.push(stateDir);

    const cfg = baseConfig();
    cfg.models = {
      providers: {
        anthropic: { baseUrl: "https://api.anthropic.com", apiKey: "x", models: [] },
        openai: { baseUrl: "https://api.openai.com/v1", apiKey: "y", models: [] },
      },
    };

    const app = createLocalOsApp({
      config: cfg,
      name: "Code Builder",
      kind: "from-scratch",
      stateDir,
    });

    expect(app.kind).toBe("from-scratch");
    expect(fs.existsSync(path.join(resolveLocalAppDir(app.id, stateDir), "src", "main.ts"))).toBe(
      true,
    );
  });

  it("supports uninstall and reinstall lifecycle", () => {
    const stateDir = makeTmpStateDir();
    cleanupDirs.push(stateDir);

    createLocalOsApp({
      config: baseConfig(),
      name: "Quick Notes",
      kind: "simple",
      stateDir,
    });

    const uninstalled = uninstallLocalOsApp({ appId: "quick-notes", stateDir });
    expect(uninstalled.status).toBe("uninstalled");

    const reinstalled = installLocalOsApp({ appId: "quick-notes", stateDir });
    expect(reinstalled.status).toBe("installed");

    const listed = listLocalOsApps(stateDir);
    expect(listed).toHaveLength(1);
    expect(listed[0]?.status).toBe("installed");
  });
});
