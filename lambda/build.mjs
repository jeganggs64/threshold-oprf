import { build } from "esbuild";
import { readdirSync, mkdirSync } from "fs";
import { join, basename } from "path";

const HANDLERS_DIR = join(import.meta.dirname, "handlers");
const OUT_DIR = join(import.meta.dirname, "dist");

mkdirSync(OUT_DIR, { recursive: true });

const handlers = readdirSync(HANDLERS_DIR).filter((f) => f.endsWith(".ts"));

for (const handler of handlers) {
  const name = basename(handler, ".ts");
  console.log(`Building ${name}...`);

  await build({
    entryPoints: [join(HANDLERS_DIR, handler)],
    bundle: true,
    platform: "node",
    target: "node20",
    outfile: join(OUT_DIR, `${name}.mjs`),
    format: "esm",
    banner: {
      // Node.js ESM compatibility for __dirname
      js: 'import { createRequire } from "module"; const require = createRequire(import.meta.url);',
    },
    external: [
      // AWS SDK v3 is included in Lambda runtime
      "@aws-sdk/*",
    ],
    minify: true,
    sourcemap: false,
  });
}

console.log(`Built ${handlers.length} Lambda handlers.`);
