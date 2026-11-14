// Builds the package twice: ES modules for bundlers, CommonJS for test runners
// that load dependencies with `require`.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const here = import.meta.dirname;
const tsc = path.join(here, "../node_modules/typescript/bin/tsc");
fs.rmSync(path.join(here, "dist"), { recursive: true, force: true });
for (const project of ["tsconfig.json", "tsconfig.cjs.json"])
  execFileSync(process.execPath, [tsc, "-p", path.join(here, project)], { stdio: "inherit" });
// The package itself is CommonJS; this marks the one directory that is not.
fs.writeFileSync(path.join(here, "dist/esm/package.json"), '{ "type": "module" }\n');
