import type { GatewayBrowserClient } from "../gateway.ts";
import type { ClaosLocalApp, ClaosStrictSecurityStatus } from "../types.ts";

type ClaosState = {
  client: GatewayBrowserClient | null;
  connected: boolean;
  claosLoading: boolean;
  claosError: string | null;
  claosApps: ClaosLocalApp[];
  claosSecurity: ClaosStrictSecurityStatus | null;
  claosBusyAction: string | null;
  claosCreateName: string;
  claosCreateType: "simple" | "from-scratch";
  claosCreateDescription: string;
  claosLastAttestation: unknown;
};

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export async function loadClaosDashboard(state: ClaosState) {
  if (!state.client || !state.connected) {
    return;
  }
  if (state.claosLoading) {
    return;
  }
  state.claosLoading = true;
  state.claosError = null;
  try {
    const [appsRes, securityRes] = await Promise.all([
      state.client.request<{ apps?: ClaosLocalApp[] }>("os.apps.list", {}),
      state.client.request<ClaosStrictSecurityStatus>("os.security.status", {}),
    ]);
    state.claosApps = Array.isArray(appsRes?.apps) ? appsRes.apps : [];
    state.claosSecurity = securityRes ?? null;
  } catch (err) {
    state.claosError = errorMessage(err);
  } finally {
    state.claosLoading = false;
  }
}

export async function createClaosApp(state: ClaosState) {
  if (!state.client || !state.connected) {
    return;
  }
  const name = state.claosCreateName.trim();
  if (!name) {
    state.claosError = "App name is required.";
    return;
  }
  state.claosBusyAction = "create";
  state.claosError = null;
  try {
    await state.client.request("os.apps.create", {
      name,
      type: state.claosCreateType,
      description: state.claosCreateDescription.trim() || undefined,
    });
    state.claosCreateName = "";
    state.claosCreateDescription = "";
    await loadClaosDashboard(state);
  } catch (err) {
    state.claosError = errorMessage(err);
  } finally {
    state.claosBusyAction = null;
  }
}

export async function installClaosApp(state: ClaosState, appId: string) {
  if (!state.client || !state.connected) {
    return;
  }
  state.claosBusyAction = `install:${appId}`;
  state.claosError = null;
  try {
    await state.client.request("os.apps.install", { appId });
    await loadClaosDashboard(state);
  } catch (err) {
    state.claosError = errorMessage(err);
  } finally {
    state.claosBusyAction = null;
  }
}

export async function uninstallClaosApp(state: ClaosState, appId: string, purge: boolean) {
  if (!state.client || !state.connected) {
    return;
  }
  state.claosBusyAction = `uninstall:${appId}`;
  state.claosError = null;
  try {
    await state.client.request("os.apps.uninstall", { appId, purge });
    await loadClaosDashboard(state);
  } catch (err) {
    state.claosError = errorMessage(err);
  } finally {
    state.claosBusyAction = null;
  }
}

export async function enforceClaosSecurity(state: ClaosState) {
  if (!state.client || !state.connected) {
    return;
  }
  state.claosBusyAction = "security:enforce";
  state.claosError = null;
  try {
    await state.client.request("os.security.enforce", {});
    await loadClaosDashboard(state);
  } catch (err) {
    state.claosError = errorMessage(err);
  } finally {
    state.claosBusyAction = null;
  }
}

export async function runClaosAttestation(state: ClaosState) {
  if (!state.client || !state.connected) {
    return;
  }
  state.claosBusyAction = "attest";
  state.claosError = null;
  try {
    state.claosLastAttestation = await state.client.request("os.attest", {});
  } catch (err) {
    state.claosError = errorMessage(err);
  } finally {
    state.claosBusyAction = null;
  }
}
