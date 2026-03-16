import { html, nothing } from "lit";
import type { ClaosLocalApp, ClaosStrictSecurityStatus } from "../types.ts";

export type ClaosViewProps = {
  connected: boolean;
  loading: boolean;
  error: string | null;
  apps: ClaosLocalApp[];
  security: ClaosStrictSecurityStatus | null;
  busyAction: string | null;
  createName: string;
  createType: "simple" | "from-scratch";
  createDescription: string;
  lastAttestation: unknown;
  onRefresh: () => void;
  onCreateNameChange: (value: string) => void;
  onCreateTypeChange: (value: "simple" | "from-scratch") => void;
  onCreateDescriptionChange: (value: string) => void;
  onCreate: () => void;
  onInstall: (appId: string) => void;
  onUninstall: (appId: string, purge: boolean) => void;
  onEnforceSecurity: () => void;
  onAttest: () => void;
};

function summaryText(
  summary: { critical: number; warn: number; info: number } | undefined,
): string {
  if (!summary) {
    return "No audit data.";
  }
  return `${summary.critical} critical · ${summary.warn} warn · ${summary.info} info`;
}

export function renderClaos(props: ClaosViewProps) {
  const strict = props.security?.strict;
  const strictHealthy = strict?.passed ?? false;
  const fromScratchHint =
    "Requires configured Anthropic + OpenAI provider credentials and latest-model generation path.";

  return html`
    <section class="grid claos-grid">
      <div class="card">
        <div class="row" style="justify-content: space-between;">
          <div>
            <div class="card-title">CLAOS Security</div>
            <div class="card-sub">Strict posture, attestation, and enforcement controls.</div>
          </div>
          <button class="btn" ?disabled=${props.loading || !props.connected} @click=${props.onRefresh}>
            ${props.loading ? "Refreshing…" : "Refresh"}
          </button>
        </div>

        ${
          strict
            ? html`
              <div class="row" style="margin-top: 12px; align-items: center;">
                <div class="pill ${strictHealthy ? "success" : "danger"}">
                  ${strictHealthy ? "Strict: PASS" : "Strict: FAIL"}
                </div>
                <span class="muted">${summaryText(strict.summary)}</span>
              </div>
              ${
                strict.findings.length > 0
                  ? html`<div class="claos-findings">
                      ${strict.findings.slice(0, 6).map(
                        (finding) => html`
                          <div class="claos-finding">
                            <div class="claos-finding__head">
                              <strong>${finding.title}</strong>
                              <span class="pill ${finding.severity === "critical" ? "danger" : "warning"}"
                                >${finding.severity}</span
                              >
                            </div>
                            <div class="muted">${finding.detail}</div>
                          </div>
                        `,
                      )}
                    </div>`
                  : html`
                      <div class="muted" style="margin-top: 10px">No strict findings.</div>
                    `
              }
            `
            : html`
                <div class="muted" style="margin-top: 10px">No security snapshot loaded yet.</div>
              `
        }

        <div class="row" style="margin-top: 12px; gap: 8px;">
          <button
            class="btn"
            ?disabled=${props.busyAction === "attest" || !props.connected}
            @click=${props.onAttest}
          >
            ${props.busyAction === "attest" ? "Running…" : "Run Attestation"}
          </button>
          <button
            class="btn primary"
            ?disabled=${props.busyAction === "security:enforce" || !props.connected}
            @click=${props.onEnforceSecurity}
          >
            ${props.busyAction === "security:enforce" ? "Enforcing…" : "Enforce Strict Policy"}
          </button>
        </div>

        ${
          props.lastAttestation
            ? html`<details style="margin-top: 10px;">
                <summary>Last Attestation Report</summary>
                <pre class="mono" style="white-space: pre-wrap;">${JSON.stringify(
                  props.lastAttestation,
                  null,
                  2,
                )}</pre>
              </details>`
            : nothing
        }
      </div>

      <div class="card">
        <div class="card-title">App Studio</div>
        <div class="card-sub">Create local apps with simple or from-scratch generation modes.</div>

        <div class="claos-create">
          <label class="field">
            <span>App Name</span>
            <input
              .value=${props.createName}
              @input=${(e: Event) => props.onCreateNameChange((e.target as HTMLInputElement).value)}
              placeholder="Daily Planner"
            />
          </label>
          <label class="field">
            <span>Creation Mode</span>
            <select
              .value=${props.createType}
              @change=${(e: Event) =>
                props.onCreateTypeChange(
                  (e.target as HTMLSelectElement).value as "simple" | "from-scratch",
                )}
            >
              <option value="simple">simple</option>
              <option value="from-scratch">from-scratch</option>
            </select>
          </label>
          <label class="field">
            <span>Description (optional)</span>
            <input
              .value=${props.createDescription}
              @input=${(e: Event) =>
                props.onCreateDescriptionChange((e.target as HTMLInputElement).value)}
              placeholder="Personal productivity app"
            />
          </label>
          <div class="callout" style="margin-top: 8px;">
            ${
              props.createType === "simple"
                ? "Simple mode uses a predefined structure and local model-assisted metadata generation."
                : fromScratchHint
            }
          </div>
          <button
            class="btn primary"
            style="margin-top: 8px;"
            ?disabled=${props.busyAction === "create" || !props.connected}
            @click=${props.onCreate}
          >
            ${props.busyAction === "create" ? "Creating…" : "Create Local App"}
          </button>
        </div>
      </div>
    </section>

    ${
      props.error
        ? html`<div class="callout danger" style="margin-top: 12px;">${props.error}</div>`
        : nothing
    }

    <section class="card" style="margin-top: 12px;">
      <div class="card-title">Installed Local Apps</div>
      <div class="card-sub">Automatic install is applied at creation based on CLAOS policy.</div>
      ${
        props.apps.length === 0
          ? html`
              <div class="muted" style="margin-top: 10px">No local apps created yet.</div>
            `
          : html`<div class="claos-app-list">
              ${props.apps.map((app) => {
                const installBusy = props.busyAction === `install:${app.id}`;
                const uninstallBusy = props.busyAction === `uninstall:${app.id}`;
                return html`
                  <div class="claos-app-item">
                    <div>
                      <div class="list-title">${app.name}</div>
                      <div class="list-sub">${app.id} · ${app.kind}</div>
                      <div class="muted">
                        Status:
                        <span class="pill ${app.status === "installed" ? "success" : "warning"}"
                          >${app.status}</span
                        >
                      </div>
                    </div>
                    <div class="row" style="justify-content: flex-end; gap: 8px;">
                      <button
                        class="btn"
                        ?disabled=${installBusy || !props.connected || app.status === "installed"}
                        @click=${() => props.onInstall(app.id)}
                      >
                        ${installBusy ? "Installing…" : "Install"}
                      </button>
                      <button
                        class="btn"
                        ?disabled=${uninstallBusy || !props.connected || app.status === "uninstalled"}
                        @click=${() => props.onUninstall(app.id, false)}
                      >
                        ${uninstallBusy ? "Uninstalling…" : "Uninstall"}
                      </button>
                      <button
                        class="btn danger"
                        ?disabled=${uninstallBusy || !props.connected}
                        @click=${() => props.onUninstall(app.id, true)}
                      >
                        ${uninstallBusy ? "Purging…" : "Purge"}
                      </button>
                    </div>
                  </div>
                `;
              })}
            </div>`
      }
    </section>
  `;
}
