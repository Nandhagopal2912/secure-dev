/**
 * @vitest-environment node
 */
import { describe, expect, it } from "vitest";

import { scanCoverageLabel } from "./scan-coverage";

describe("scanCoverageLabel", () => {
  it("shows a total when the scan asked for specific scanners", () => {
    expect(scanCoverageLabel(1, 2)).toBe("1 of 2 reported");
    expect(scanCoverageLabel(0, 2)).toBe("0 of 2 reported");
  });

  it("shows no total when the scan asked for every supporting scanner", () => {
    expect(scanCoverageLabel(2, 0)).toBe("2 reported");
    expect(scanCoverageLabel(0, 0)).toBe("0 reported");
  });
});
