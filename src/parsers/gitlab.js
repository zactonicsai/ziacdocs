import fs from "fs";
import yaml from "js-yaml";

export function parseGitlabFile(filepath) {
  const raw = fs.readFileSync(filepath, "utf-8");
  const doc = yaml.load(raw);

  // Jobs are top-level keys excluding reserved keywords.
  const reserved = new Set([
    "stages", "default", "include", "workflow", "variables",
    "image", "services", "before_script", "after_script", "cache"
  ]);

  const jobs = [];
  for (const [k, v] of Object.entries(doc || {})) {
    if (reserved.has(k)) continue;
    if (typeof v === "object" && v) jobs.push({ name: k, body: v });
  }

  return {
    file: filepath,
    stages: doc?.stages || [],
    variables: doc?.variables || {},
    workflow: doc?.workflow || null,
    default: doc?.default || null,
    jobs
  };
}
