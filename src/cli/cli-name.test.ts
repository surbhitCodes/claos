import { describe, expect, it } from "vitest";
import { replaceCliName, resolveCliName } from "./cli-name.js";

describe("cli name", () => {
  it("detects claos executable basename", () => {
    expect(resolveCliName(["node", "/usr/local/bin/claos"]).trim()).toBe("claos");
  });

  it("replaces openclaw prefix with claos", () => {
    expect(replaceCliName("openclaw status", "claos")).toBe("claos status");
  });

  it("replaces wrapped openclaw prefix with claos", () => {
    expect(replaceCliName("pnpm openclaw status", "claos")).toBe("pnpm claos status");
  });

  it("keeps non-cli prefixes unchanged", () => {
    expect(replaceCliName("echo openclaw", "claos")).toBe("echo openclaw");
  });
});
