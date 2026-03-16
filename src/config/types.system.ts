export type OpenClawOsSecurityProfile = "strict" | "standard" | "dev";

export type OpenClawOsBootIntegrity = "required" | "recommended" | "off";

export type OpenClawOsRuntimeSandbox = "required" | "preferred" | "off";

export type OpenClawOsInferenceRouting = "hybrid-classified" | "local-only" | "cloud-allowed";

export type OpenClawOsAppKind = "simple" | "from-scratch";

export type OpenClawOsConfig = {
  security?: {
    /** OpenClaw OS hardening profile selection. */
    profile?: OpenClawOsSecurityProfile;
  };
  boot?: {
    /** Boot-chain integrity expectation. */
    integrity?: OpenClawOsBootIntegrity;
  };
  runtime?: {
    /** Runtime sandbox posture for tool execution. */
    sandbox?: OpenClawOsRuntimeSandbox;
  };
  privacy?: {
    /** Routing policy for local-vs-cloud inference. */
    inferenceRouting?: OpenClawOsInferenceRouting;
  };
  telemetry?: {
    /** External telemetry gate (opt-in only by default). */
    enabled?: boolean;
  };
  autonomy?: {
    /** Enable autonomous agent workflows (sandboxed execution defaults). */
    enabled?: boolean;
    /** Default local-first model for autonomous tasks. */
    defaultModel?: string;
  };
  apps?: {
    /** Automatically install local apps immediately after creation. */
    autoInstall?: boolean;
    simple?: {
      /** Local-first model used for metadata-first simple app generation. */
      model?: string;
    };
    fromScratch?: {
      /**
       * Require both Anthropic and OpenAI credentials for from-scratch generation.
       * This mode is intended for latest-model quality code synthesis.
       */
      requireProviders?: boolean;
      /** Anthropic model used for from-scratch generation. */
      anthropicModel?: string;
      /** OpenAI model used for from-scratch generation. */
      openaiModel?: string;
    };
  };
};

export type SystemConfig = {
  os?: OpenClawOsConfig;
};
