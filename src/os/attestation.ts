import fs from "node:fs/promises";
import { runCommandWithTimeout } from "../process/exec.js";

export type OsAttestationStatus = "pass" | "fail" | "unknown";

export type OsAttestationCheck = {
  id: string;
  title: string;
  status: OsAttestationStatus;
  required: boolean;
  detail: string;
};

export type OsAttestationReport = {
  ts: number;
  platform: NodeJS.Platform;
  checks: OsAttestationCheck[];
  summary: {
    pass: number;
    fail: number;
    unknown: number;
  };
};

type ProbeResult = {
  ok: boolean;
  stdout: string;
  stderr: string;
};

async function exists(pathname: string): Promise<boolean> {
  try {
    await fs.access(pathname);
    return true;
  } catch {
    return false;
  }
}

async function runProbe(argv: string[]): Promise<ProbeResult> {
  try {
    const result = await runCommandWithTimeout(argv, { timeoutMs: 8_000 });
    return {
      ok: result.code === 0,
      stdout: result.stdout.trim(),
      stderr: result.stderr.trim(),
    };
  } catch (error) {
    return {
      ok: false,
      stdout: "",
      stderr: String(error),
    };
  }
}

function summarize(checks: OsAttestationCheck[]): OsAttestationReport["summary"] {
  let pass = 0;
  let fail = 0;
  let unknown = 0;
  for (const check of checks) {
    if (check.status === "pass") {
      pass += 1;
      continue;
    }
    if (check.status === "fail") {
      fail += 1;
      continue;
    }
    unknown += 1;
  }
  return { pass, fail, unknown };
}

async function detectSecureBoot(): Promise<OsAttestationCheck> {
  const hasEfi = await exists("/sys/firmware/efi");
  if (!hasEfi) {
    return {
      id: "secure-boot",
      title: "Secure Boot",
      status: "fail",
      required: true,
      detail: "EFI firmware path missing; system likely booted without UEFI Secure Boot.",
    };
  }

  const mokutil = await runProbe(["mokutil", "--sb-state"]);
  if (mokutil.ok) {
    const lower = mokutil.stdout.toLowerCase();
    if (lower.includes("enabled")) {
      return {
        id: "secure-boot",
        title: "Secure Boot",
        status: "pass",
        required: true,
        detail: mokutil.stdout,
      };
    }
    if (lower.includes("disabled")) {
      return {
        id: "secure-boot",
        title: "Secure Boot",
        status: "fail",
        required: true,
        detail: mokutil.stdout,
      };
    }
  }

  const bootctl = await runProbe(["bootctl", "status"]);
  if (bootctl.ok) {
    const secureBootLine = bootctl.stdout
      .split("\n")
      .find((line) => line.toLowerCase().includes("secure boot"));
    if (secureBootLine?.toLowerCase().includes("enabled")) {
      return {
        id: "secure-boot",
        title: "Secure Boot",
        status: "pass",
        required: true,
        detail: secureBootLine.trim(),
      };
    }
    if (secureBootLine?.toLowerCase().includes("disabled")) {
      return {
        id: "secure-boot",
        title: "Secure Boot",
        status: "fail",
        required: true,
        detail: secureBootLine.trim(),
      };
    }
  }

  return {
    id: "secure-boot",
    title: "Secure Boot",
    status: "unknown",
    required: true,
    detail: "Unable to determine Secure Boot status (mokutil/bootctl unavailable).",
  };
}

async function detectTpm(): Promise<OsAttestationCheck> {
  const hasTpmrm = await exists("/dev/tpmrm0");
  const hasTpm = hasTpmrm || (await exists("/dev/tpm0"));
  if (!hasTpm) {
    return {
      id: "tpm-device",
      title: "TPM Device",
      status: "fail",
      required: true,
      detail: "No TPM device detected at /dev/tpmrm0 or /dev/tpm0.",
    };
  }

  return {
    id: "tpm-device",
    title: "TPM Device",
    status: "pass",
    required: true,
    detail: hasTpmrm ? "Detected /dev/tpmrm0." : "Detected /dev/tpm0.",
  };
}

async function detectMeasuredBoot(): Promise<OsAttestationCheck> {
  const result = await runProbe(["tpm2_pcrread", "sha256:0,7"]);
  if (result.ok) {
    return {
      id: "measured-boot",
      title: "Measured Boot PCR Read",
      status: "pass",
      required: true,
      detail: "Successfully read PCRs 0 and 7 via tpm2_pcrread.",
    };
  }

  return {
    id: "measured-boot",
    title: "Measured Boot PCR Read",
    status: "unknown",
    required: true,
    detail: result.stderr || "tpm2-tools unavailable or PCR read failed.",
  };
}

async function detectRootEncryption(): Promise<OsAttestationCheck> {
  const source = await runProbe(["findmnt", "-n", "-o", "SOURCE", "/"]);
  if (!source.ok || !source.stdout) {
    return {
      id: "root-encryption",
      title: "Root Filesystem Encryption",
      status: "unknown",
      required: true,
      detail: source.stderr || "Unable to detect root filesystem source.",
    };
  }

  if (source.stdout.startsWith("/dev/mapper/")) {
    return {
      id: "root-encryption",
      title: "Root Filesystem Encryption",
      status: "pass",
      required: true,
      detail: `Root mounted from encrypted mapper device (${source.stdout}).`,
    };
  }

  return {
    id: "root-encryption",
    title: "Root Filesystem Encryption",
    status: "fail",
    required: true,
    detail: `Root mounted from ${source.stdout}; expected an encrypted mapper path.`,
  };
}

async function detectReadOnlyRoot(): Promise<OsAttestationCheck> {
  const opts = await runProbe(["findmnt", "-n", "-o", "OPTIONS", "/"]);
  if (!opts.ok || !opts.stdout) {
    return {
      id: "readonly-root",
      title: "Read-only Root",
      status: "unknown",
      required: false,
      detail: opts.stderr || "Unable to inspect root mount options.",
    };
  }

  if (opts.stdout.split(",").includes("ro")) {
    return {
      id: "readonly-root",
      title: "Read-only Root",
      status: "pass",
      required: false,
      detail: "Root filesystem is mounted read-only.",
    };
  }

  return {
    id: "readonly-root",
    title: "Read-only Root",
    status: "fail",
    required: false,
    detail: "Root filesystem is writable (expected read-only for immutable base mode).",
  };
}

export async function collectOsAttestation(): Promise<OsAttestationReport> {
  if (process.platform !== "linux") {
    const checks: OsAttestationCheck[] = [
      {
        id: "platform-linux",
        title: "Linux Host",
        status: "fail",
        required: true,
        detail: `OpenClaw OS attestation currently supports Linux hosts only (got ${process.platform}).`,
      },
    ];
    return {
      ts: Date.now(),
      platform: process.platform,
      checks,
      summary: summarize(checks),
    };
  }

  const checks = await Promise.all([
    detectSecureBoot(),
    detectTpm(),
    detectMeasuredBoot(),
    detectRootEncryption(),
    detectReadOnlyRoot(),
  ]);

  return {
    ts: Date.now(),
    platform: process.platform,
    checks,
    summary: summarize(checks),
  };
}
