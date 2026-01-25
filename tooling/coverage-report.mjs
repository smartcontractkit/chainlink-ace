import { spawnSync } from "node:child_process";

const coverage = spawnSync("forge", ["coverage", "--report", "lcov"], { stdio: "inherit", shell: true });
if ((coverage.status ?? 1) !== 0) process.exit(coverage.status ?? 1);

// genhtml is optional (commonly available on Linux via lcov package).
const genhtmlCheck = spawnSync("genhtml", ["--version"], { stdio: "ignore", shell: true });
if ((genhtmlCheck.status ?? 1) !== 0) {
  console.warn("genhtml not found; skipping HTML coverage report generation.");
  process.exit(0);
}

const genhtml = spawnSync(
  "genhtml",
  ["lcov.info", "--branch-coverage", "--output-dir", "coverage"],
  { stdio: "inherit", shell: true },
);
process.exit(genhtml.status ?? 1);

