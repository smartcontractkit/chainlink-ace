import fs from "node:fs";

const paths = ["cache", "out"];
for (const p of paths) {
  fs.rmSync(p, { recursive: true, force: true });
}

