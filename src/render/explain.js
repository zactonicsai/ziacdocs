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
