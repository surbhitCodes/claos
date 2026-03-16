import crypto from "node:crypto";
import type { OpenClawConfig } from "../config/config.js";
import type {
  OpenClawOsBootIntegrity,
  OpenClawOsInferenceRouting,
  OpenClawOsRuntimeSandbox,
  OpenClawOsSecurityProfile,
} from "../config/types.system.js";

export type OpenClawOsDefaults = {
  securityProfile: OpenClawOsSecurityProfile;
  bootIntegrity: OpenClawOsBootIntegrity;
  runtimeSandbox: OpenClawOsRuntimeSandbox;
  inferenceRouting: OpenClawOsInferenceRouting;
  telemetryEnabled: boolean;
  autonomyEnabled: boolean;
  autonomyDefaultModel: string;
  appsAutoInstall: boolean;
  appsSimpleModel: string;
  appsFromScratchRequireProviders: boolean;
  appsFromScratchAnthropicModel: string;
  appsFromScratchOpenAIModel: string;
};

export const OPENCLAW_OS_DEFAULTS: OpenClawOsDefaults = {
  securityProfile: "strict",
  bootIntegrity: "required",
  runtimeSandbox: "required",
  inferenceRouting: "hybrid-classified",
  telemetryEnabled: false,
  autonomyEnabled: true,
  autonomyDefaultModel: "ollama/qwen3:4b",
  appsAutoInstall: true,
  appsSimpleModel: "ollama/qwen3:4b",
  appsFromScratchRequireProviders: true,
  appsFromScratchAnthropicModel: "anthropic/claude-sonnet-4-6",
  appsFromScratchOpenAIModel: "openai/gpt-5.4",
};

export type OsEnforcementResult = {
  config: OpenClawConfig;
  changes: string[];
  generatedGatewayToken: boolean;
};

function cloneOrCreate<T extends Record<string, unknown>>(value: T | undefined): T {
  return value ? { ...value } : ({} as T);
}

export function applyOpenClawOsDefaults(cfg: OpenClawConfig): OpenClawConfig {
  const profile = cfg.system?.os?.security?.profile ?? OPENCLAW_OS_DEFAULTS.securityProfile;
  const integrity = cfg.system?.os?.boot?.integrity ?? OPENCLAW_OS_DEFAULTS.bootIntegrity;
  const sandbox = cfg.system?.os?.runtime?.sandbox ?? OPENCLAW_OS_DEFAULTS.runtimeSandbox;
  const routing =
    cfg.system?.os?.privacy?.inferenceRouting ?? OPENCLAW_OS_DEFAULTS.inferenceRouting;
  const telemetry = cfg.system?.os?.telemetry?.enabled ?? OPENCLAW_OS_DEFAULTS.telemetryEnabled;
  const autonomyEnabled = cfg.system?.os?.autonomy?.enabled ?? OPENCLAW_OS_DEFAULTS.autonomyEnabled;
  const autonomyDefaultModel =
    cfg.system?.os?.autonomy?.defaultModel ?? OPENCLAW_OS_DEFAULTS.autonomyDefaultModel;
  const appsAutoInstall = cfg.system?.os?.apps?.autoInstall ?? OPENCLAW_OS_DEFAULTS.appsAutoInstall;
  const appsSimpleModel =
    cfg.system?.os?.apps?.simple?.model ?? OPENCLAW_OS_DEFAULTS.appsSimpleModel;
  const appsFromScratchRequireProviders =
    cfg.system?.os?.apps?.fromScratch?.requireProviders ??
    OPENCLAW_OS_DEFAULTS.appsFromScratchRequireProviders;
  const appsFromScratchAnthropicModel =
    cfg.system?.os?.apps?.fromScratch?.anthropicModel ??
    OPENCLAW_OS_DEFAULTS.appsFromScratchAnthropicModel;
  const appsFromScratchOpenAIModel =
    cfg.system?.os?.apps?.fromScratch?.openaiModel ??
    OPENCLAW_OS_DEFAULTS.appsFromScratchOpenAIModel;

  return {
    ...cfg,
    system: {
      ...cfg.system,
      os: {
        ...cfg.system?.os,
        security: {
          ...cfg.system?.os?.security,
          profile,
        },
        boot: {
          ...cfg.system?.os?.boot,
          integrity,
        },
        runtime: {
          ...cfg.system?.os?.runtime,
          sandbox,
        },
        privacy: {
          ...cfg.system?.os?.privacy,
          inferenceRouting: routing,
        },
        telemetry: {
          ...cfg.system?.os?.telemetry,
          enabled: telemetry,
        },
        autonomy: {
          ...cfg.system?.os?.autonomy,
          enabled: autonomyEnabled,
          defaultModel: autonomyDefaultModel,
        },
        apps: {
          ...cfg.system?.os?.apps,
          autoInstall: appsAutoInstall,
          simple: {
            ...cfg.system?.os?.apps?.simple,
            model: appsSimpleModel,
          },
          fromScratch: {
            ...cfg.system?.os?.apps?.fromScratch,
            requireProviders: appsFromScratchRequireProviders,
            anthropicModel: appsFromScratchAnthropicModel,
            openaiModel: appsFromScratchOpenAIModel,
          },
        },
      },
    },
  };
}

export function enforceOpenClawOsSecurityBaseline(source: OpenClawConfig): OsEnforcementResult {
  let generatedGatewayToken = false;
  const cfg = applyOpenClawOsDefaults(source);
  const changes: string[] = [];

  const gateway = cloneOrCreate(cfg.gateway as Record<string, unknown> | undefined);
  const gatewayAuth = cloneOrCreate(
    (cfg.gateway?.auth as Record<string, unknown> | undefined) ?? undefined,
  );
  const tools = cloneOrCreate(cfg.tools as Record<string, unknown> | undefined);
  const exec = cloneOrCreate((cfg.tools?.exec as Record<string, unknown> | undefined) ?? undefined);
  const elevated = cloneOrCreate(
    (cfg.tools?.elevated as Record<string, unknown> | undefined) ?? undefined,
  );
  const agents = cloneOrCreate(cfg.agents as Record<string, unknown> | undefined);
  const agentDefaults = cloneOrCreate(
    (cfg.agents?.defaults as Record<string, unknown> | undefined) ?? undefined,
  );
  const sandbox = cloneOrCreate(
    (cfg.agents?.defaults?.sandbox as Record<string, unknown> | undefined) ?? undefined,
  );
  const models = cloneOrCreate(cfg.models as Record<string, unknown> | undefined);
  const modelProviders = cloneOrCreate(
    (cfg.models?.providers as Record<string, unknown> | undefined) ?? undefined,
  );
  const ollamaProvider = cloneOrCreate(
    (cfg.models?.providers?.ollama as Record<string, unknown> | undefined) ?? undefined,
  );

  if (cfg.gateway?.bind !== "loopback") {
    gateway.bind = "loopback";
    changes.push("gateway.bind -> loopback");
  }

  const authMode = typeof cfg.gateway?.auth?.mode === "string" ? cfg.gateway.auth.mode : "";
  if (authMode !== "token") {
    gatewayAuth.mode = "token";
    changes.push("gateway.auth.mode -> token");
  }

  const hasToken = (() => {
    const token = cfg.gateway?.auth?.token;
    if (typeof token === "string") {
      return token.trim().length > 0;
    }
    if (token && typeof token === "object") {
      return true;
    }
    return false;
  })();
  if (!hasToken) {
    gatewayAuth.token = crypto.randomBytes(24).toString("hex");
    generatedGatewayToken = true;
    changes.push("gateway.auth.token -> generated random token");
  }

  const execHost = typeof cfg.tools?.exec?.host === "string" ? cfg.tools.exec.host : undefined;
  if (execHost !== "sandbox") {
    exec.host = "sandbox";
    changes.push("tools.exec.host -> sandbox");
  }

  const execSecurity =
    typeof cfg.tools?.exec?.security === "string" ? cfg.tools.exec.security : undefined;
  if (execSecurity !== "full") {
    exec.security = "full";
    changes.push("tools.exec.security -> full");
  }

  if (cfg.tools?.exec?.ask !== "off") {
    exec.ask = "off";
    changes.push("tools.exec.ask -> off");
  }

  if (cfg.tools?.elevated?.enabled !== false) {
    elevated.enabled = false;
    changes.push("tools.elevated.enabled -> false");
  }

  if (cfg.agents?.defaults?.sandbox?.mode !== "all") {
    sandbox.mode = "all";
    changes.push("agents.defaults.sandbox.mode -> all");
  }

  if (cfg.tools?.profile !== "coding") {
    tools.profile = "coding";
    changes.push("tools.profile -> coding");
  }

  const currentPrimary =
    typeof cfg.agents?.defaults?.model === "string"
      ? cfg.agents.defaults.model
      : cfg.agents?.defaults?.model?.primary;
  if (currentPrimary !== OPENCLAW_OS_DEFAULTS.autonomyDefaultModel) {
    agentDefaults.model = {
      primary: OPENCLAW_OS_DEFAULTS.autonomyDefaultModel,
      fallbacks: ["ollama/qwen2.5:3b"],
    };
    changes.push(`agents.defaults.model.primary -> ${OPENCLAW_OS_DEFAULTS.autonomyDefaultModel}`);
  }

  const ollamaApi =
    typeof cfg.models?.providers?.ollama?.api === "string" ? cfg.models.providers.ollama.api : "";
  if (ollamaApi !== "ollama") {
    ollamaProvider.api = "ollama";
    changes.push("models.providers.ollama.api -> ollama");
  }
  const ollamaBaseUrl =
    typeof cfg.models?.providers?.ollama?.baseUrl === "string"
      ? cfg.models.providers.ollama.baseUrl
      : "";
  if (!ollamaBaseUrl.trim()) {
    ollamaProvider.baseUrl = "http://127.0.0.1:11434";
    changes.push("models.providers.ollama.baseUrl -> http://127.0.0.1:11434");
  }

  const autonomy = cloneOrCreate(
    (cfg.system?.os?.autonomy as Record<string, unknown> | undefined) ?? undefined,
  );
  if (cfg.system?.os?.autonomy?.enabled !== true) {
    autonomy.enabled = true;
    changes.push("system.os.autonomy.enabled -> true");
  }
  if (cfg.system?.os?.autonomy?.defaultModel !== OPENCLAW_OS_DEFAULTS.autonomyDefaultModel) {
    autonomy.defaultModel = OPENCLAW_OS_DEFAULTS.autonomyDefaultModel;
    changes.push(`system.os.autonomy.defaultModel -> ${OPENCLAW_OS_DEFAULTS.autonomyDefaultModel}`);
  }
  const apps = cloneOrCreate(
    (cfg.system?.os?.apps as Record<string, unknown> | undefined) ?? undefined,
  );
  const appsSimple = cloneOrCreate(
    (cfg.system?.os?.apps?.simple as Record<string, unknown> | undefined) ?? undefined,
  );
  const appsFromScratch = cloneOrCreate(
    (cfg.system?.os?.apps?.fromScratch as Record<string, unknown> | undefined) ?? undefined,
  );

  if (cfg.system?.os?.apps?.autoInstall !== OPENCLAW_OS_DEFAULTS.appsAutoInstall) {
    apps.autoInstall = OPENCLAW_OS_DEFAULTS.appsAutoInstall;
    changes.push(`system.os.apps.autoInstall -> ${OPENCLAW_OS_DEFAULTS.appsAutoInstall}`);
  }
  if (cfg.system?.os?.apps?.simple?.model !== OPENCLAW_OS_DEFAULTS.appsSimpleModel) {
    appsSimple.model = OPENCLAW_OS_DEFAULTS.appsSimpleModel;
    changes.push(`system.os.apps.simple.model -> ${OPENCLAW_OS_DEFAULTS.appsSimpleModel}`);
  }
  if (
    cfg.system?.os?.apps?.fromScratch?.requireProviders !==
    OPENCLAW_OS_DEFAULTS.appsFromScratchRequireProviders
  ) {
    appsFromScratch.requireProviders = OPENCLAW_OS_DEFAULTS.appsFromScratchRequireProviders;
    changes.push(
      `system.os.apps.fromScratch.requireProviders -> ${OPENCLAW_OS_DEFAULTS.appsFromScratchRequireProviders}`,
    );
  }
  if (
    cfg.system?.os?.apps?.fromScratch?.anthropicModel !==
    OPENCLAW_OS_DEFAULTS.appsFromScratchAnthropicModel
  ) {
    appsFromScratch.anthropicModel = OPENCLAW_OS_DEFAULTS.appsFromScratchAnthropicModel;
    changes.push(
      `system.os.apps.fromScratch.anthropicModel -> ${OPENCLAW_OS_DEFAULTS.appsFromScratchAnthropicModel}`,
    );
  }
  if (
    cfg.system?.os?.apps?.fromScratch?.openaiModel !==
    OPENCLAW_OS_DEFAULTS.appsFromScratchOpenAIModel
  ) {
    appsFromScratch.openaiModel = OPENCLAW_OS_DEFAULTS.appsFromScratchOpenAIModel;
    changes.push(
      `system.os.apps.fromScratch.openaiModel -> ${OPENCLAW_OS_DEFAULTS.appsFromScratchOpenAIModel}`,
    );
  }

  const resolvedOllamaBaseUrl = ollamaProvider.baseUrl ?? cfg.models?.providers?.ollama?.baseUrl;
  const nextOllamaProvider = {
    ...cfg.models?.providers?.ollama,
    ...ollamaProvider,
    baseUrl:
      typeof resolvedOllamaBaseUrl === "string" && resolvedOllamaBaseUrl.trim().length > 0
        ? resolvedOllamaBaseUrl
        : "http://127.0.0.1:11434",
    models: Array.isArray(cfg.models?.providers?.ollama?.models)
      ? cfg.models?.providers?.ollama?.models
      : [],
  };

  const next: OpenClawConfig = {
    ...cfg,
    gateway: {
      ...cfg.gateway,
      ...gateway,
      auth: {
        ...cfg.gateway?.auth,
        ...gatewayAuth,
      },
    },
    tools: {
      ...cfg.tools,
      ...tools,
      exec: {
        ...cfg.tools?.exec,
        ...exec,
      },
      elevated: {
        ...cfg.tools?.elevated,
        ...elevated,
      },
    },
    agents: {
      ...cfg.agents,
      ...agents,
      defaults: {
        ...cfg.agents?.defaults,
        ...agentDefaults,
        sandbox: {
          ...cfg.agents?.defaults?.sandbox,
          ...sandbox,
        },
      },
    },
    models: {
      ...cfg.models,
      ...models,
      providers: {
        ...cfg.models?.providers,
        ...modelProviders,
        ollama: nextOllamaProvider,
      },
    },
    system: {
      ...cfg.system,
      os: {
        ...cfg.system?.os,
        autonomy: {
          ...cfg.system?.os?.autonomy,
          ...autonomy,
        },
        apps: {
          ...cfg.system?.os?.apps,
          ...apps,
          simple: {
            ...cfg.system?.os?.apps?.simple,
            ...appsSimple,
          },
          fromScratch: {
            ...cfg.system?.os?.apps?.fromScratch,
            ...appsFromScratch,
          },
        },
      },
    },
  };

  return { config: next, changes, generatedGatewayToken };
}

export function summarizeOsPolicy(cfg: OpenClawConfig): Record<string, string | boolean> {
  return {
    securityProfile: cfg.system?.os?.security?.profile ?? OPENCLAW_OS_DEFAULTS.securityProfile,
    bootIntegrity: cfg.system?.os?.boot?.integrity ?? OPENCLAW_OS_DEFAULTS.bootIntegrity,
    runtimeSandbox: cfg.system?.os?.runtime?.sandbox ?? OPENCLAW_OS_DEFAULTS.runtimeSandbox,
    inferenceRouting:
      cfg.system?.os?.privacy?.inferenceRouting ?? OPENCLAW_OS_DEFAULTS.inferenceRouting,
    telemetryEnabled: cfg.system?.os?.telemetry?.enabled ?? OPENCLAW_OS_DEFAULTS.telemetryEnabled,
    autonomyEnabled: cfg.system?.os?.autonomy?.enabled ?? OPENCLAW_OS_DEFAULTS.autonomyEnabled,
    autonomyDefaultModel:
      cfg.system?.os?.autonomy?.defaultModel ?? OPENCLAW_OS_DEFAULTS.autonomyDefaultModel,
    appsAutoInstall: cfg.system?.os?.apps?.autoInstall ?? OPENCLAW_OS_DEFAULTS.appsAutoInstall,
    appsSimpleModel: cfg.system?.os?.apps?.simple?.model ?? OPENCLAW_OS_DEFAULTS.appsSimpleModel,
    appsFromScratchRequireProviders:
      cfg.system?.os?.apps?.fromScratch?.requireProviders ??
      OPENCLAW_OS_DEFAULTS.appsFromScratchRequireProviders,
    appsFromScratchAnthropicModel:
      cfg.system?.os?.apps?.fromScratch?.anthropicModel ??
      OPENCLAW_OS_DEFAULTS.appsFromScratchAnthropicModel,
    appsFromScratchOpenAIModel:
      cfg.system?.os?.apps?.fromScratch?.openaiModel ??
      OPENCLAW_OS_DEFAULTS.appsFromScratchOpenAIModel,
  };
}
