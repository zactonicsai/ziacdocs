# ziacdocs

Below is a **simple Node.js “IaC + GitLab doc generator”** you can drop into a repo. It:

* Scans a folder for **Terraform** (`.tf`) and **GitLab CI** (`.gitlab-ci.yml/.yaml`)
* Parses Terraform HCL → JSON
* Uses **static JSON “type catalogs”** (AWS + Networking + Java + React + Security/Auth) to explain what things mean
* Generates **human-readable Markdown** docs into `./docs/generated`

It also includes **sample Markdown outputs** and a small **sample full-stack secure setup** (network segmentation + auth + security).

---

## 1) Project structure

```text
iac-docgen/
  package.json
  README.md
  src/
    index.js
    scan.js
    parsers/
      terraform.js
      gitlab.js
    render/
      markdown.js
      explain.js
    catalogs/
      aws.json
      networking.json
      security-auth.json
      java.json
      react.json
      gitlab.json
  samples/
    terraform/
      main.tf
      network.tf
      security.tf
    gitlab/
      .gitlab-ci.yml
  docs/
    samples/
      SAMPLE_TERRAFORM_DOC.md
      SAMPLE_GITLAB_DOC.md
```

---

## 2) `package.json`

```json
{
  "name": "iac-docgen",
  "version": "1.0.0",
  "type": "module",
  "description": "Generate human-readable Markdown documentation for Terraform IaC and GitLab CI pipelines using static catalogs.",
  "main": "src/index.js",
  "scripts": {
    "doc": "node src/index.js --in ./samples --out ./docs/generated",
    "doc:repo": "node src/index.js --in . --out ./docs/generated"
  },
  "dependencies": {
    "hcl-to-json": "^0.4.1",
    "js-yaml": "^4.1.0"
  }
}
```

Install:

```bash
npm install
```

Run on samples:

```bash
npm run doc
```

Run on your repo:

```bash
npm run doc:repo
```

---

## 3) Static JSON catalogs (the “type system”)

### `src/catalogs/aws.json`

```json
{
  "resourceTypes": {
    "aws_vpc": {
      "category": "Networking",
      "summary": "Creates a Virtual Private Cloud (VPC) to isolate resources in a private network boundary.",
      "keyConcerns": ["CIDR planning", "segmentation", "logging", "least privilege routing"]
    },
    "aws_subnet": {
      "category": "Networking",
      "summary": "Creates a subnet inside a VPC. Used for public/private segmentation and AZ placement.",
      "keyConcerns": ["public vs private", "route tables", "NAT design", "AZ redundancy"]
    },
    "aws_security_group": {
      "category": "Security",
      "summary": "Defines stateful firewall rules for inbound/outbound traffic.",
      "keyConcerns": ["least privilege ports", "no 0.0.0.0/0 on admin ports", "egress control", "tagging/ownership"]
    },
    "aws_lb": {
      "category": "Networking",
      "summary": "Creates an Application/Network Load Balancer to distribute traffic across targets.",
      "keyConcerns": ["TLS", "WAF", "private vs public", "health checks"]
    },
    "aws_ecs_service": {
      "category": "Compute",
      "summary": "Runs and maintains a desired count of containers on ECS (often behind an ALB).",
      "keyConcerns": ["IAM task roles", "private subnets", "secrets", "autoscaling"]
    },
    "aws_rds_instance": {
      "category": "Data",
      "summary": "Provisions a managed relational database instance.",
      "keyConcerns": ["private subnet", "encryption", "backups", "rotation", "no public access"]
    }
  }
}
```

### `src/catalogs/networking.json`

```json
{
  "concepts": {
    "segmentation": {
      "summary": "Separate systems into zones (public, private-app, private-data) to reduce blast radius.",
      "details": [
        "Public subnet: only internet-facing entrypoints (ALB, NAT GW if required).",
        "Private app subnet: application services not directly accessible from the internet.",
        "Private data subnet: databases and sensitive services; tight security groups and no outbound by default if possible."
      ]
    },
    "routes": {
      "summary": "Route tables determine how traffic moves between subnets, IGW, NAT, and peering links.",
      "details": [
        "Public route table typically has 0.0.0.0/0 -> Internet Gateway.",
        "Private route table typically has 0.0.0.0/0 -> NAT Gateway (if egress needed).",
        "Data subnets often have no default route to the internet (egress restricted)."
      ]
    }
  }
}
```

### `src/catalogs/security-auth.json`

```json
{
  "concepts": {
    "authn_authz": {
      "summary": "Authentication verifies identity; authorization enforces access control.",
      "details": [
        "Prefer OIDC/OAuth2 with short-lived tokens for services.",
        "Use a centralized IdP (e.g., Keycloak, Cognito) for users and service-to-service identities.",
        "Enforce least privilege IAM and app roles; log access decisions."
      ]
    },
    "secrets": {
      "summary": "Secrets must not be stored in git; use a secrets manager and rotate credentials.",
      "details": [
        "Use AWS Secrets Manager / SSM Parameter Store with KMS encryption.",
        "Inject secrets at runtime (task env or sidecar), not baked into images.",
        "Rotate DB passwords and API keys; audit access."
      ]
    },
    "logging_monitoring": {
      "summary": "Centralize logs/metrics/traces and alert on security and reliability signals.",
      "details": [
        "VPC Flow Logs for network visibility.",
        "CloudTrail for API auditing.",
        "App logs with request IDs; structured JSON logs when possible."
      ]
    }
  }
}
```

### `src/catalogs/java.json`

```json
{
  "concepts": {
    "spring_security": {
      "summary": "Common approach: Spring Boot as OAuth2 Resource Server verifying JWTs from an IdP.",
      "details": [
        "Validate issuer/audience and enforce scopes/roles.",
        "Prefer stateless JWT validation; avoid server sessions for APIs unless needed.",
        "Protect admin endpoints and enable rate-limiting at edge."
      ]
    }
  }
}
```

### `src/catalogs/react.json`

```json
{
  "concepts": {
    "spa_auth": {
      "summary": "React SPA should use OIDC Authorization Code Flow with PKCE.",
      "details": [
        "Avoid storing long-lived tokens in localStorage when possible.",
        "Prefer short-lived access tokens and refresh via secure flows.",
        "Use an API gateway / BFF if you need stronger token handling."
      ]
    }
  }
}
```

### `src/catalogs/gitlab.json`

```json
{
  "keywords": {
    "stages": "Defines pipeline phases executed in order (build -> test -> security -> deploy).",
    "rules": "Controls when jobs run (branch, tag, MR, changes).",
    "artifacts": "Files passed between jobs (build outputs, reports).",
    "cache": "Speeds up builds by caching dependencies.",
    "environment": "Deployment targets with optional URLs and review apps."
  },
  "jobPatterns": {
    "security_scan": {
      "summary": "Security scanning stage (SAST/Dependency/Secrets/IaC).",
      "recommendations": [
        "Fail pipeline on critical findings for protected branches.",
        "Store reports as artifacts and publish summaries.",
        "Scan Terraform and container images before deploy."
      ]
    }
  }
}
```

---

## 4) Source code

### `src/index.js`

```js
import fs from "fs";
import path from "path";
import { scanRepo } from "./scan.js";
import { parseTerraformFiles } from "./parsers/terraform.js";
import { parseGitlabFile } from "./parsers/gitlab.js";
import { renderMarkdownBundle } from "./render/markdown.js";

function arg(name, fallback = null) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return fallback;
  return process.argv[idx + 1] ?? fallback;
}

const inDir = path.resolve(arg("--in", "."));
const outDir = path.resolve(arg("--out", "./docs/generated"));

fs.mkdirSync(outDir, { recursive: true });

const catalogsDir = path.resolve("src/catalogs");
const catalogs = {
  aws: JSON.parse(fs.readFileSync(path.join(catalogsDir, "aws.json"), "utf-8")),
  networking: JSON.parse(fs.readFileSync(path.join(catalogsDir, "networking.json"), "utf-8")),
  securityAuth: JSON.parse(fs.readFileSync(path.join(catalogsDir, "security-auth.json"), "utf-8")),
  java: JSON.parse(fs.readFileSync(path.join(catalogsDir, "java.json"), "utf-8")),
  react: JSON.parse(fs.readFileSync(path.join(catalogsDir, "react.json"), "utf-8")),
  gitlab: JSON.parse(fs.readFileSync(path.join(catalogsDir, "gitlab.json"), "utf-8"))
};

const files = scanRepo(inDir);

// Terraform
const tfFiles = files.filter(f => f.endsWith(".tf"));
const tf = await parseTerraformFiles(tfFiles);

// GitLab
const gitlabPath = files.find(f => /(\.gitlab-ci\.ya?ml)$/i.test(path.basename(f)));
const gitlab = gitlabPath ? parseGitlabFile(gitlabPath) : null;

// Render
const bundle = renderMarkdownBundle({
  repoRoot: inDir,
  terraform: tf,
  gitlab,
  catalogs
});

for (const doc of bundle.docs) {
  const dest = path.join(outDir, doc.filename);
  fs.writeFileSync(dest, doc.content, "utf-8");
}

const indexPath = path.join(outDir, "INDEX.md");
fs.writeFileSync(indexPath, bundle.index, "utf-8");

console.log(`✅ Generated ${bundle.docs.length + 1} Markdown files into: ${outDir}`);
```

### `src/scan.js`

```js
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
```

### `src/parsers/terraform.js`

```js
import fs from "fs";
import hclToJson from "hcl-to-json";

/**
 * Produces a normalized Terraform model:
 *  - resources: [{type, name, body, file}]
 *  - variables: [{name, body, file}]
 *  - outputs:   [{name, body, file}]
 *  - modules:   [{name, body, file}]
 */
export async function parseTerraformFiles(tfPaths) {
  const model = { resources: [], variables: [], outputs: [], modules: [], files: [] };

  for (const file of tfPaths) {
    const raw = fs.readFileSync(file, "utf-8");
    model.files.push(file);

    let parsed;
    try {
      parsed = hclToJson(raw);
    } catch (e) {
      model.files.push(`${file} (PARSE_ERROR: ${e.message})`);
      continue;
    }

    // Terraform HCL-to-JSON output uses keys like "resource", "variable", etc.
    if (parsed.resource) {
      for (const [rtype, blocks] of Object.entries(parsed.resource)) {
        for (const [rname, body] of Object.entries(blocks)) {
          model.resources.push({ type: rtype, name: rname, body, file });
        }
      }
    }

    if (parsed.variable) {
      for (const [vname, body] of Object.entries(parsed.variable)) {
        model.variables.push({ name: vname, body, file });
      }
    }

    if (parsed.output) {
      for (const [oname, body] of Object.entries(parsed.output)) {
        model.outputs.push({ name: oname, body, file });
      }
    }

    if (parsed.module) {
      for (const [mname, body] of Object.entries(parsed.module)) {
        model.modules.push({ name: mname, body, file });
      }
    }
  }

  return model;
}
```

### `src/parsers/gitlab.js`

```js
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
```

### `src/render/explain.js`

```js
function asArray(x) {
  if (!x) return [];
  return Array.isArray(x) ? x : [x];
}

function pick(obj, key, fallback = null) {
  return obj && Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : fallback;
}

export function explainTerraformResource(resource, catalogs) {
  const awsType = catalogs.aws?.resourceTypes?.[resource.type];
  const base = {
    category: awsType?.category || "Uncategorized",
    summary: awsType?.summary || "No catalog entry found for this resource type.",
    keyConcerns: awsType?.keyConcerns || []
  };

  const body = resource.body || {};
  const notes = [];

  // High-value heuristics for security/network segmentation documentation
  if (resource.type === "aws_vpc") {
    notes.push(`**CIDR**: \`${pick(body, "cidr_block", "unknown")}\``);
    notes.push(`Enable DNS: \`enable_dns_support=${pick(body, "enable_dns_support", "unknown")}\`, \`enable_dns_hostnames=${pick(body, "enable_dns_hostnames", "unknown")}\``);
  }

  if (resource.type === "aws_subnet") {
    notes.push(`**Subnet CIDR**: \`${pick(body, "cidr_block", "unknown")}\``);
    notes.push(`**Availability Zone**: \`${pick(body, "availability_zone", "unknown")}\``);
    notes.push(`**Public IP on launch**: \`${pick(body, "map_public_ip_on_launch", "unknown")}\``);
  }

  if (resource.type === "aws_security_group") {
    const ingress = asArray(body.ingress);
    const egress = asArray(body.egress);
    notes.push(`**Ingress rules**: ${ingress.length}`);
    notes.push(`**Egress rules**: ${egress.length}`);

    // detect risky patterns
    const risky = [];
    for (const rule of ingress) {
      const cidrs = asArray(rule.cidr_blocks);
      const from = rule.from_port;
      const to = rule.to_port;
      if (cidrs.includes("0.0.0.0/0") && (from === 22 || from === 3389 || to === 22 || to === 3389)) {
        risky.push(`Ingress allows admin port (${from}-${to}) from 0.0.0.0/0`);
      }
    }
    if (risky.length) notes.push(`⚠️ **Risk flags**: ${risky.join("; ")}`);
  }

  if (resource.type === "aws_rds_instance") {
    notes.push(`**Engine**: \`${pick(body, "engine", "unknown")}\``);
    notes.push(`**Publicly accessible**: \`${pick(body, "publicly_accessible", "unknown")}\``);
    notes.push(`**Storage encrypted**: \`${pick(body, "storage_encrypted", "unknown")}\``);
    notes.push(`**Backup retention**: \`${pick(body, "backup_retention_period", "unknown")}\``);
  }

  return { ...base, notes };
}

export function explainGitlabJob(job, catalogs) {
  const body = job.body || {};
  const stage = body.stage || "test";
  const tags = asArray(body.tags).join(", ") || "—";
  const rules = body.rules ? "Yes" : "No";
  const artifacts = body.artifacts ? "Yes" : "No";

  const hints = [];
  const script = asArray(body.script).join("\n");
  if (/tfsec|checkov|trivy|semgrep|gitleaks/i.test(script)) {
    const pattern = catalogs.gitlab?.jobPatterns?.security_scan;
    if (pattern?.summary) hints.push(pattern.summary);
    if (pattern?.recommendations?.length) hints.push(...pattern.recommendations);
  }

  return { stage, tags, rules, artifacts, hints };
}

export function explainArchitecture(catalogs) {
  const seg = catalogs.networking?.concepts?.segmentation;
  const auth = catalogs.securityAuth?.concepts?.authn_authz;

  return {
    segmentation: seg,
    auth: auth
  };
}
```

### `src/render/markdown.js`

```js
import path from "path";
import { explainTerraformResource, explainGitlabJob, explainArchitecture } from "./explain.js";

function rel(repoRoot, file) {
  return path.relative(repoRoot, file).replaceAll("\\", "/");
}

function mdEscape(s) {
  return String(s ?? "").replaceAll("\r", "");
}

function codeBlock(lang, content) {
  return `\n\`\`\`${lang}\n${mdEscape(content)}\n\`\`\`\n`;
}

export function renderMarkdownBundle({ repoRoot, terraform, gitlab, catalogs }) {
  const docs = [];

  // 1) Terraform doc
  const tfDoc = renderTerraformDoc({ repoRoot, terraform, catalogs });
  docs.push({ filename: "TERRAFORM.md", content: tfDoc });

  // 2) GitLab doc
  const glDoc = gitlab
    ? renderGitlabDoc({ repoRoot, gitlab, catalogs })
    : `# GitLab CI\n\nNo \`.gitlab-ci.yml\` found.\n`;
  docs.push({ filename: "GITLAB_CI.md", content: glDoc });

  // 3) Architecture/Security overview (from catalogs)
  const archDoc = renderArchitectureDoc({ catalogs });
  docs.push({ filename: "ARCHITECTURE_SECURITY.md", content: archDoc });

  const index = `# Documentation Index

- [Terraform Infrastructure](./TERRAFORM.md)
- [GitLab CI Pipeline](./GITLAB_CI.md)
- [Architecture & Security Notes](./ARCHITECTURE_SECURITY.md)

Generated by **iac-docgen**.
`;

  return { docs, index };
}

function renderTerraformDoc({ repoRoot, terraform, catalogs }) {
  const lines = [];
  lines.push(`# Terraform Infrastructure Documentation`);
  lines.push(``);
  lines.push(`## Files discovered`);
  for (const f of terraform.files) lines.push(`- \`${rel(repoRoot, f)}\``);

  lines.push(``);
  lines.push(`## High-level intent`);
  lines.push(
    `This section explains what the Terraform configuration is building and how it is wired together, ` +
    `with extra emphasis on **security, authentication/authorization, and network segmentation**.`
  );

  // Modules
  lines.push(``);
  lines.push(`## Modules`);
  if (!terraform.modules.length) {
    lines.push(`No Terraform modules detected.`);
  } else {
    for (const m of terraform.modules) {
      lines.push(`### \`module.${m.name}\``);
      lines.push(`- Defined in: \`${rel(repoRoot, m.file)}\``);
      lines.push(`- Source: \`${m.body?.source ?? "unknown"}\``);
      if (m.body?.version) lines.push(`- Version: \`${m.body.version}\``);
      lines.push(``);
    }
  }

  // Variables
  lines.push(`## Variables`);
  if (!terraform.variables.length) {
    lines.push(`No variables detected.`);
  } else {
    for (const v of terraform.variables) {
      const b = v.body || {};
      lines.push(`### \`${v.name}\``);
      lines.push(`- Defined in: \`${rel(repoRoot, v.file)}\``);
      if (b.type) lines.push(`- Type: \`${JSON.stringify(b.type)}\``);
      if (b.description) lines.push(`- Description: ${b.description}`);
      if (b.default !== undefined) lines.push(`- Default: \`${JSON.stringify(b.default)}\``);
      lines.push(``);
    }
  }

  // Resources
  lines.push(`## Resources`);
  if (!terraform.resources.length) {
    lines.push(`No resources detected.`);
  } else {
    // group by category then type
    const grouped = new Map();
    for (const r of terraform.resources) {
      const e = explainTerraformResource(r, catalogs);
      const key = `${e.category}::${r.type}`;
      if (!grouped.has(key)) grouped.set(key, { category: e.category, type: r.type, items: [] });
      grouped.get(key).items.push({ r, e });
    }

    const sortedKeys = [...grouped.keys()].sort();
    for (const key of sortedKeys) {
      const g = grouped.get(key);
      lines.push(`### ${g.category}: \`${g.type}\``);
      const catEntry = catalogs.aws?.resourceTypes?.[g.type];
      if (catEntry?.summary) lines.push(`**What this is:** ${catEntry.summary}`);
      if (catEntry?.keyConcerns?.length) {
        lines.push(`**Key concerns:** ${catEntry.keyConcerns.map(x => `\`${x}\``).join(", ")}`);
      }
      lines.push(``);

      for (const { r, e } of g.items) {
        lines.push(`#### \`${r.type}.${r.name}\``);
        lines.push(`- File: \`${rel(repoRoot, r.file)}\``);
        lines.push(`- Purpose: ${e.summary}`);
        if (e.notes.length) {
          lines.push(`- Notable configuration:`);
          for (const n of e.notes) lines.push(`  - ${n}`);
        }

        // include a small snippet of the raw body keys for transparency
        const keys = Object.keys(r.body || {}).slice(0, 12);
        if (keys.length) lines.push(`- Config keys (partial): ${keys.map(k => `\`${k}\``).join(", ")}`);
        lines.push(``);
      }
    }
  }

  // Outputs
  lines.push(`## Outputs`);
  if (!terraform.outputs.length) {
    lines.push(`No outputs detected.`);
  } else {
    for (const o of terraform.outputs) {
      lines.push(`### \`${o.name}\``);
      lines.push(`- Defined in: \`${rel(repoRoot, o.file)}\``);
      if (o.body?.description) lines.push(`- Description: ${o.body.description}`);
      if (o.body?.value) lines.push(`- Value expression present (not evaluated).`);
      lines.push(``);
    }
  }

  // Security checklist
  lines.push(`## Security & segmentation checklist (opinionated)`);
  lines.push(`- Prefer **private subnets** for app + data; only expose an ALB/API gateway publicly.`);
  lines.push(`- Avoid SSH/RDP from \`0.0.0.0/0\`. Use SSM Session Manager or a bastion with strict allowlists.`);
  lines.push(`- Enable **VPC Flow Logs** and **CloudTrail**; centralize logs.`);
  lines.push(`- Encrypt data at rest (KMS) and in transit (TLS).`);
  lines.push(`- Use Secrets Manager/SSM for secrets; do not commit credentials.`);
  lines.push(`- Minimize security group egress; prefer explicit allowlists for sensitive tiers.`);
  lines.push(``);

  return lines.join("\n");
}

function renderGitlabDoc({ repoRoot, gitlab, catalogs }) {
  const lines = [];
  lines.push(`# GitLab CI Pipeline Documentation`);
  lines.push(``);
  lines.push(`- File: \`${rel(repoRoot, gitlab.file)}\``);

  // Keywords explanations
  lines.push(``);
  lines.push(`## Key pipeline concepts`);
  for (const [k, v] of Object.entries(catalogs.gitlab?.keywords || {})) {
    lines.push(`- **${k}**: ${v}`);
  }

  lines.push(``);
  lines.push(`## Stages`);
  if (gitlab.stages?.length) {
    lines.push(gitlab.stages.map(s => `- \`${s}\``).join("\n"));
  } else {
    lines.push(`No explicit stages found (GitLab will use defaults if jobs define stages).`);
  }

  lines.push(``);
  lines.push(`## Variables`);
  const vars = gitlab.variables || {};
  const varKeys = Object.keys(vars);
  if (!varKeys.length) lines.push(`No global variables declared.`);
  else {
    for (const k of varKeys.sort()) {
      const v = vars[k];
      const display = typeof v === "string" ? v : JSON.stringify(v);
      lines.push(`- \`${k}\`: \`${display}\``);
    }
  }

  lines.push(``);
  lines.push(`## Jobs`);
  if (!gitlab.jobs.length) {
    lines.push(`No jobs detected.`);
  } else {
    // group by stage
    const stageMap = new Map();
    for (const job of gitlab.jobs) {
      const info = explainGitlabJob(job, catalogs);
      const stage = info.stage || "test";
      if (!stageMap.has(stage)) stageMap.set(stage, []);
      stageMap.get(stage).push({ job, info });
    }

    for (const stage of [...stageMap.keys()].sort()) {
      lines.push(`### Stage: \`${stage}\``);
      for (const { job, info } of stageMap.get(stage)) {
        lines.push(`#### \`${job.name}\``);
        lines.push(`- Tags: ${info.tags}`);
        lines.push(`- Uses rules: ${info.rules}`);
        lines.push(`- Publishes artifacts: ${info.artifacts}`);

        const script = Array.isArray(job.body?.script) ? job.body.script.join("\n") : (job.body?.script || "");
        if (script) {
          lines.push(``);
          lines.push(`**Script**:`);
          lines.push(codeBlock("bash", script).trimEnd());
        }

        if (info.hints?.length) {
          lines.push(`**Security notes / recommendations**:`);
          for (const h of info.hints) lines.push(`- ${h}`);
        }
        lines.push(``);
      }
    }
  }

  lines.push(`## Secure full-stack CI guidance (recommended)`);
  lines.push(`- Add SAST + dependency scanning (e.g., Semgrep, Trivy, OWASP Dependency-Check).`);
  lines.push(`- Add secrets scanning (e.g., gitleaks).`);
  lines.push(`- Add IaC scanning for Terraform (e.g., tfsec/checkov).`);
  lines.push(`- Gate deploy jobs to protected branches/tags and require approvals.`);
  lines.push(`- Use OIDC to cloud provider for CI auth (avoid long-lived AWS keys).`);
  lines.push(``);

  return lines.join("\n");
}

function renderArchitectureDoc({ catalogs }) {
  const lines = [];
  const arch = explainArchitecture(catalogs);

  lines.push(`# Architecture & Security Notes`);
  lines.push(``);
  lines.push(`## Network segmentation`);
  if (arch.segmentation) {
    lines.push(`**Summary:** ${arch.segmentation.summary}`);
    lines.push(``);
    for (const d of arch.segmentation.details || []) lines.push(`- ${d}`);
  } else {
    lines.push(`No segmentation catalog entry found.`);
  }

  lines.push(``);
  lines.push(`## Authentication & Authorization`);
  if (arch.auth) {
    lines.push(`**Summary:** ${arch.auth.summary}`);
    lines.push(``);
    for (const d of arch.auth.details || []) lines.push(`- ${d}`);
  } else {
    lines.push(`No auth catalog entry found.`);
  }

  lines.push(``);
  lines.push(`## Java API notes (Spring Boot)`);
  const java = catalogs.java?.concepts?.spring_security;
  if (java) {
    lines.push(`**Summary:** ${java.summary}`);
    lines.push(``);
    for (const d of java.details || []) lines.push(`- ${d}`);
  }

  lines.push(``);
  lines.push(`## React SPA notes`);
  const react = catalogs.react?.concepts?.spa_auth;
  if (react) {
    lines.push(`**Summary:** ${react.summary}`);
    lines.push(``);
    for (const d of react.details || []) lines.push(`- ${d}`);
  }

  return lines.join("\n");
}
```

---

## 5) Sample IaC + GitLab inputs (full stack + security + segmentation)

### `samples/terraform/network.tf`

```hcl
resource "aws_vpc" "main" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "demo-vpc" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  tags = { Name = "public-a" }
}

resource "aws_subnet" "private_app_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.11.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "private-app-a" }
}

resource "aws_subnet" "private_data_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.21.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "private-data-a" }
}
```

### `samples/terraform/security.tf`

```hcl
resource "aws_security_group" "alb_sg" {
  name   = "alb-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
    description = "Public HTTPS"
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["10.20.0.0/16"]
    description = "Only to VPC"
  }
}

resource "aws_security_group" "app_sg" {
  name   = "app-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol        = "tcp"
    from_port       = 8080
    to_port         = 8080
    security_groups = [aws_security_group.alb_sg.id]
    description     = "Only ALB to app"
  }

  egress {
    protocol    = "tcp"
    from_port   = 5432
    to_port     = 5432
    cidr_blocks = ["10.20.21.0/24"]
    description = "App to DB subnet only"
  }
}
```

### `samples/gitlab/.gitlab-ci.yml`

```yaml
stages:
  - build
  - test
  - security
  - deploy

variables:
  NODE_ENV: "production"

build_web:
  stage: build
  image: node:20
  script:
    - npm ci
    - npm run build
  artifacts:
    paths:
      - dist/

test_api:
  stage: test
  image: maven:3-eclipse-temurin-21
  script:
    - mvn -q test

iac_security_scan:
  stage: security
  image: alpine:3.19
  script:
    - apk add --no-cache curl bash
    - echo "Run tfsec/checkov here for Terraform scanning"
    - echo "Run gitleaks here to detect secrets"
  artifacts:
    when: always
    paths:
      - reports/

deploy_prod:
  stage: deploy
  image: alpine:3.19
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
  script:
    - echo "Deploy using OIDC to cloud provider (no long-lived keys)"
```

---

## 6) Sample Markdown outputs (what the tool generates)

### `docs/samples/SAMPLE_TERRAFORM_DOC.md`

```md
# Terraform Infrastructure Documentation

## Files discovered
- `samples/terraform/network.tf`
- `samples/terraform/security.tf`

## High-level intent
This section explains what the Terraform configuration is building and how it is wired together, with extra emphasis on **security, authentication/authorization, and network segmentation**.

## Resources

### Networking: `aws_vpc`
**What this is:** Creates a Virtual Private Cloud (VPC) to isolate resources in a private network boundary.
**Key concerns:** `CIDR planning`, `segmentation`, `logging`, `least privilege routing`

#### `aws_vpc.main`
- File: `samples/terraform/network.tf`
- Purpose: Creates a Virtual Private Cloud (VPC) to isolate resources in a private network boundary.
- Notable configuration:
  - **CIDR**: `10.20.0.0/16`
  - Enable DNS: `enable_dns_support=true`, `enable_dns_hostnames=true`
- Config keys (partial): `cidr_block`, `enable_dns_support`, `enable_dns_hostnames`, `tags`

### Networking: `aws_subnet`
**What this is:** Creates a subnet inside a VPC. Used for public/private segmentation and AZ placement.
**Key concerns:** `public vs private`, `route tables`, `NAT design`, `AZ redundancy`

#### `aws_subnet.public_a`
- File: `samples/terraform/network.tf`
- Notable configuration:
  - **Subnet CIDR**: `10.20.1.0/24`
  - **Availability Zone**: `us-east-1a`
  - **Public IP on launch**: `true`

#### `aws_subnet.private_app_a`
- File: `samples/terraform/network.tf`
- Notable configuration:
  - **Subnet CIDR**: `10.20.11.0/24`
  - **Availability Zone**: `us-east-1a`
  - **Public IP on launch**: `unknown`

#### `aws_subnet.private_data_a`
- File: `samples/terraform/network.tf`
- Notable configuration:
  - **Subnet CIDR**: `10.20.21.0/24`
  - **Availability Zone**: `us-east-1a`

### Security: `aws_security_group`
**What this is:** Defines stateful firewall rules for inbound/outbound traffic.
**Key concerns:** `least privilege ports`, `no 0.0.0.0/0 on admin ports`, `egress control`, `tagging/ownership`

#### `aws_security_group.alb_sg`
- File: `samples/terraform/security.tf`
- Notable configuration:
  - **Ingress rules**: 1
  - **Egress rules**: 1

#### `aws_security_group.app_sg`
- File: `samples/terraform/security.tf`
- Notable configuration:
  - **Ingress rules**: 1
  - **Egress rules**: 1

## Security & segmentation checklist (opinionated)
- Prefer **private subnets** for app + data; only expose an ALB/API gateway publicly.
- Avoid SSH/RDP from `0.0.0.0/0`. Use SSM Session Manager or a bastion with strict allowlists.
- Enable **VPC Flow Logs** and **CloudTrail**; centralize logs.
- Encrypt data at rest (KMS) and in transit (TLS).
- Use Secrets Manager/SSM for secrets; do not commit credentials.
- Minimize security group egress; prefer explicit allowlists for sensitive tiers.
```

### `docs/samples/SAMPLE_GITLAB_DOC.md`

````md
# GitLab CI Pipeline Documentation

- File: `samples/gitlab/.gitlab-ci.yml`

## Key pipeline concepts
- **stages**: Defines pipeline phases executed in order (build -> test -> security -> deploy).
- **rules**: Controls when jobs run (branch, tag, MR, changes).
- **artifacts**: Files passed between jobs (build outputs, reports).
- **cache**: Speeds up builds by caching dependencies.
- **environment**: Deployment targets with optional URLs and review apps.

## Stages
- `build`
- `test`
- `security`
- `deploy`

## Jobs

### Stage: `security`

#### `iac_security_scan`
- Uses rules: No
- Publishes artifacts: Yes

**Script**
```bash
apk add --no-cache curl bash
echo "Run tfsec/checkov here for Terraform scanning"
echo "Run gitleaks here to detect secrets"
````

**Security notes / recommendations**

* Security scanning stage (SAST/Dependency/Secrets/IaC).
* Fail pipeline on critical findings for protected branches.
* Store reports as artifacts and publish summaries.
* Scan Terraform and container images before deploy.

````

---

## 7) Quick README you can include

### `README.md`
```md
# iac-docgen

Generate **Markdown documentation** for:
- Terraform (`.tf`)
- GitLab CI (`.gitlab-ci.yml/.yaml`)

## Run
```bash
npm install
npm run doc:repo
````

Docs output:

* `docs/generated/INDEX.md`
* `docs/generated/TERRAFORM.md`
* `docs/generated/GITLAB_CI.md`
* `docs/generated/ARCHITECTURE_SECURITY.md`

```
iac-docgen/
  package.json
  README.md
  src/
    index.js
    scan.js
    parsers/
      terraform.js
      gitlab.js
    render/
      markdown.js
      explain.js
    catalogs/
      aws.json
      networking.json
      security-auth.json
      java.json
      react.json
      gitlab.json
  samples/
    terraform/
      main.tf
      network.tf
      security.tf
    gitlab/
      .gitlab-ci.yml
  docs/
    samples/
      SAMPLE_TERRAFORM_DOC.md
      SAMPLE_GITLAB_DOC.md
```