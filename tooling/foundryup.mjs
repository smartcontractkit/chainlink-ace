import fs from "node:fs";
import { spawnSync } from "node:child_process";

const version = fs.readFileSync(".foundry-version", "utf8").trim();
if (!version) {
  console.error("Missing .foundry-version");
  process.exit(1);
}

const res = spawnSync("foundryup", ["--version", version], { stdio: "inherit", shell: true });
process.exit(res.status ?? 1);

