#!/usr/bin/env bun

import { build } from "bun";
import { mkdir } from "fs/promises";

console.log("🚀 Starting build process...");

// Ensure dist directory exists
await mkdir("dist", { recursive: true });

console.log("📦 Building ESM for browsers...");
const esmResult = await build({
  entrypoints: ["src/index.ts"],
  outdir: "dist",
  target: "browser",
  format: "esm",
  minify: true,
  sourcemap: "external",
  external: ["@solana/web3.js", "@solana/spl-memo", "tweetnacl", "bs58"],
  naming: {
    entry: "index.js",
    chunk: "[name].js",
    asset: "[name].[ext]"
  }
});

console.log("📦 Building CJS for Node.js...");
const cjsResult = await build({
  entrypoints: ["src/index.ts"],
  outdir: "dist",
  target: "node",
  format: "cjs",
  minify: true,
  sourcemap: "external",
  external: ["@solana/web3.js", "@solana/spl-memo", "tweetnacl", "bs58"],
  naming: {
    entry: "index.cjs",
    chunk: "[name].cjs",
    asset: "[name].[ext]"
  }
});

console.log("✅ Build completed successfully!");
console.log(`📁 ESM bundle: dist/index.js (${Math.round(esmResult.outputs[0].size / 1024)}KB)`);
console.log(`📁 CJS bundle: dist/index.cjs (${Math.round(cjsResult.outputs[0].size / 1024)}KB)`);
