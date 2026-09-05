const fs = require("node:fs");

// Fail closed on unfamiliar diagnostics. Whitespace can change with terminal
// width, but both the heading and the complete explanation must match.
try {
  const log = fs.readFileSync(process.argv[2], "utf8");
  const headings = [...log.matchAll(/^[ \t]*(?:Error|Warning)\b[^\r\n]*/gm)];
  let errors = 0;
  for (let index = 0; index < headings.length; index++) {
    const heading = headings[index];
    const summary = heading[0].trim();
    if (summary.startsWith("Warning:")) continue;
    errors++;
    const body = log.slice(heading.index + heading[0].length, headings[index + 1]?.index);
    const paragraphs = body.trim().split(/\r?\n[ \t]*\r?\n/).map(p => p.replace(/\s+/g, " ").trim());
    let explanation;
    if (summary === "Error: Invalid count argument") {
      explanation = /^The "count" value depends on resource attributes that cannot be determined until apply, so Terraform cannot predict how many instances will be created\.(?: |$)/;
    } else if (summary === "Error: Invalid for_each argument") {
      explanation = /^The "for_each" (?:map includes keys|set includes values) derived from resource attributes that cannot be determined until apply, and so Terraform cannot determine the full set of keys that will identify the instances of this resource\.(?: |$)/;
    } else {
      process.exit(1);
    }
    if (!paragraphs.some(p => explanation.test(p))) process.exit(1);
  }
  process.exit(errors > 0 ? 0 : 1);
} catch {
  process.exit(1);
}
