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
