import fs from "fs";
import path from "path";

const IGNORE = new Set(["node_modules", ".git", ".terraform", "dist", "build", "target"]);

export function scanRepo(rootDir) {
  const out = [];
  function walk(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      if (IGNORE.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else out.push(full);
    }
  }
  walk(rootDir);
  return out;
}
