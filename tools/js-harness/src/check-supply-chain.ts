import { readdir } from "node:fs/promises";
import { join } from "node:path";

export {};

type DirectoryEntry = {
  isDirectory(): boolean;
  isFile(): boolean;
  name: string;
};
type DirectoryEntries = DirectoryEntry[];

const packageJson = await readJson("package.json");

const dependencySections = ["dependencies", "devDependencies", "optionalDependencies"] as const;
const floatingSpecPattern = /^(latest|next|canary|beta|alpha|rc|\*|workspace:|file:|link:|git\+|github:|https?:|[~^><=])/;
const forbiddenLockSpecPattern = /(?:latest|workspace:|file:|link:|git\+|github:|https?:)/;
const installHooks = ["preinstall", "install", "postinstall"] as const;
const bunfigRequiredSettings = new Map([
  ["auto", '"disable"'],
  ["exact", "true"],
  ["frozenLockfile", "true"],
  ["ignoreScripts", "true"],
  ["linker", '"isolated"'],
  ["saveTextLockfile", "true"],
]);

let failed = false;

for (const section of dependencySections) {
  const dependencies = asRecord(packageJson[section]);
  for (const [name, spec] of Object.entries(dependencies)) {
    if (typeof spec !== "string" || floatingSpecPattern.test(spec)) {
      failed = true;
      console.error(`floating dependency spec: ${section}.${name}=${String(spec)}`);
    }
  }
}

const trustedDependencies = packageJson.trustedDependencies;
if (Array.isArray(trustedDependencies) && trustedDependencies.length > 0) {
  failed = true;
  console.error(`trustedDependencies must stay empty: ${trustedDependencies.join(", ")}`);
} else if (!Array.isArray(trustedDependencies)) {
  failed = true;
  console.error("trustedDependencies must be present and empty");
}

const packageManager = packageJson.packageManager;
if (packageManager !== "bun@1.3.13") {
  failed = true;
  console.error(`packageManager must be pinned to bun@1.3.13: ${String(packageManager)}`);
}

const lockfile = await Bun.file("bun.lock").text();
if (forbiddenLockSpecPattern.test(lockfile)) {
  failed = true;
  console.error("bun.lock contains a forbidden non-registry or tag spec");
}

const bunfig = await Bun.file("bunfig.toml").text();
for (const [key, expected] of bunfigRequiredSettings) {
  const settingPattern = new RegExp(`^${key}\\s*=\\s*${escapeRegExp(expected)}\\s*$`, "m");
  if (!settingPattern.test(bunfig)) {
    failed = true;
    console.error(`bunfig.toml must contain ${key} = ${expected}`);
  }
}

await assertNoInstallHooks("node_modules/.bun");

if (failed) {
  process.exit(1);
}

console.log("supply-chain policy ok");

async function readJson(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await Bun.file(path).text()) as Record<string, unknown>;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }

  return value as Record<string, unknown>;
}

async function assertNoInstallHooks(root: string): Promise<void> {
  const rootEntries = await readDirectory(root);
  if (!rootEntries) {
    failed = true;
    console.error(`${root} is missing; run bun install before supply-chain checks`);
    return;
  }

  for await (const packageJsonPath of packageJsonFiles(root, rootEntries)) {
    const dependencyPackageJson = await readJson(packageJsonPath);
    const scripts = asRecord(dependencyPackageJson.scripts);
    const presentHooks = installHooks.filter((hook) => typeof scripts[hook] === "string");
    if (presentHooks.length > 0) {
      failed = true;
      console.error(
        `install lifecycle hook in ${packageJsonPath}: ${presentHooks.join(", ")}`,
      );
    }
  }
}

async function* packageJsonFiles(
  root: string,
  entries?: DirectoryEntries,
): AsyncGenerator<string> {
  const directoryEntries = entries ?? ((await readdir(root, { withFileTypes: true })) as DirectoryEntries);

  for (const entry of directoryEntries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      yield* packageJsonFiles(path);
    } else if (entry.isFile() && entry.name === "package.json") {
      yield path;
    }
  }
}

async function readDirectory(path: string): Promise<DirectoryEntries | null> {
  try {
    return (await readdir(path, { withFileTypes: true })) as DirectoryEntries;
  } catch (error) {
    const code = error instanceof Error && "code" in error ? error.code : undefined;
    if (code === "ENOENT") {
      return null;
    }

    throw error;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
