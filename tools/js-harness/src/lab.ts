import { existsSync } from "node:fs";

// The harness uses `playwright-core` instead of `playwright` so dependency
// installation does not need browser-downloader lifecycle scripts. Reown Lab's
// own functional tests are Playwright-based:
// https://github.com/reown-com/appkit/blob/main/apps/laboratory/tests/README.md
import { chromium, type Browser, type Page } from "playwright-core";

export {};

type LabCommand = "routes" | "catalog" | "capture-uri";
type RouteKind = "appkit" | "core";
type RouteExpectation = "valid" | "known-broken";
type CatalogCategory =
  | "appkit-core"
  | "bitcoin"
  | "custom"
  | "ethers"
  | "ethers5"
  | "featured"
  | "flags"
  | "multichain"
  | "pay"
  | "permissions"
  | "siwx"
  | "solana"
  | "testing"
  | "ton"
  | "tron"
  | "verify"
  | "wagmi";

type LabScenario = {
  category: CatalogCategory;
  expectation: RouteExpectation;
  name: string;
  note: string;
  publicLink: boolean;
  route: string;
  routeKind: RouteKind;
};

type ParsedArgs = {
  baseUrl: string;
  command: LabCommand;
  headed: boolean;
  json: boolean;
  scenario: string;
  showUri: boolean;
  timeoutMs: number;
  validate: boolean;
};

type RouteStatus = {
  bodyHint: string;
  expectation: RouteExpectation;
  name: string;
  ok: boolean;
  route: string;
  status: number | null;
};

const DEFAULT_BASE_URL = "https://lab.reown.com/";
const DEFAULT_TIMEOUT_MS = 15_000;
const ROUTE_VALIDATION_CONCURRENCY = 8;
const LAB_HOME_REFERENCE =
  "https://github.com/reown-com/appkit/blob/main/apps/laboratory/src/utils/DataUtil.ts";
const LAB_CONFIG_REFERENCE =
  "https://github.com/reown-com/appkit/blob/main/apps/laboratory/src/constants/appKitConfigs.ts";
const LAB_APPKIT_ROUTE_REFERENCE =
  "https://github.com/reown-com/appkit/blob/main/apps/laboratory/app/appkit/page.tsx";
const LAB_SIGN_CLIENT_REFERENCE =
  "https://github.com/reown-com/appkit/blob/main/apps/laboratory/app/appkit-core/sign-client/page.tsx";

const LAB_CATALOG: LabScenario[] = [
  scenario("appkit-core", "core-sign-client", "/appkit-core/sign-client/", "direct SignClient interop target", false, "core"),
  scenario("featured", "wagmi", "/appkit?name=wagmi", "default EVM AppKit route", true),
  scenario("featured", "multichain-all", "/appkit?name=multichain-all", "EVM, Solana, Bitcoin, TON, and TRON adapters", true),
  scenario("featured", "multichain-no-adapters", "/appkit?name=multichain-no-adapters", "adapter-free AppKit route", true),
  scenario("featured", "headless", "/appkit?name=headless", "headless AppKit route", true),
  scenario("wagmi", "wagmi-all", "/appkit?name=wagmi-all", "wagmi plus SIWE", true),
  scenario("wagmi", "wagmi-no-email", "/appkit?name=wagmi-no-email", "wagmi without email", true),
  scenario("wagmi", "wagmi-no-socials", "/appkit?name=wagmi-no-socials", "wagmi without socials", true),
  scenario("permissions", "wagmi-permission-sync", "/appkit?name=wagmi-permission-sync", "source-defined ERC-7715 sync permissions route", false),
  scenario("permissions", "wagmi-permission-async", "/appkit?name=wagmi-permission-async", "source-defined ERC-7715 async permissions route", false),
  scenario("permissions", "wagmi-permissions-sync", "/appkit?name=wagmi-permissions-sync", "homepage plural alias currently renders Config not found", true, "appkit", "known-broken"),
  scenario("permissions", "wagmi-permissions-async", "/appkit?name=wagmi-permissions-async", "homepage plural alias currently renders Config not found", true, "appkit", "known-broken"),
  scenario("ethers", "ethers", "/appkit?name=ethers", "ethers adapter", true),
  scenario("ethers", "ethers-all", "/appkit?name=ethers-all", "ethers plus SIWE", true),
  scenario("ethers", "ethers-no-email", "/appkit?name=ethers-no-email", "ethers without email", true),
  scenario("ethers", "ethers-no-socials", "/appkit?name=ethers-no-socials", "ethers without socials", true),
  scenario("ethers5", "ethers5", "/appkit?name=ethers5", "ethers v5 adapter", true),
  scenario("ethers5", "ethers5-all", "/appkit?name=ethers5-all", "ethers v5 plus SIWE", true),
  scenario("ethers5", "ethers5-no-socials", "/appkit?name=ethers5-no-socials", "ethers v5 without socials", true),
  scenario("solana", "solana", "/appkit?name=solana", "Solana adapter", true),
  scenario("solana", "solana-no-email", "/appkit?name=solana-no-email", "Solana without email", true),
  scenario("solana", "solana-no-socials", "/appkit?name=solana-no-socials", "Solana without socials", true),
  scenario("bitcoin", "bitcoin", "/appkit?name=bitcoin", "Bitcoin adapter", true),
  scenario("ton", "ton", "/appkit?name=ton", "TON adapter", true),
  scenario("tron", "tron", "/appkit?name=tron", "TRON adapter", true),
  scenario("multichain", "multichain-wagmi-solana", "/appkit?name=multichain-wagmi-solana", "wagmi plus Solana adapters", true),
  scenario("multichain", "multichain-wagmi-bitcoin", "/appkit?name=multichain-wagmi-bitcoin", "wagmi plus Bitcoin adapters", true),
  scenario("multichain", "multichain-ethers-solana", "/appkit?name=multichain-ethers-solana", "ethers plus Solana adapters", true),
  scenario("multichain", "multichain-ethers5-solana", "/appkit?name=multichain-ethers5-solana", "ethers v5 plus Solana adapters", true),
  scenario("siwx", "siwx-default", "/appkit?name=siwx-default", "default multichain SIWX", true),
  scenario("siwx", "reown-authentication", "/appkit?name=reown-authentication", "Reown Authentication SIWX", true),
  scenario("pay", "pay-default", "/appkit?name=pay-default", "AppKit Pay route", true),
  scenario("testing", "universal-links", "/appkit?name=universal-links", "universal-links mobile routing", true),
  scenario("flags", "flag-enable-reconnect-wagmi", "/appkit?name=flag-enable-reconnect-wagmi", "wagmi reconnect disabled", true),
  scenario("flags", "flag-enable-reconnect-ethers", "/appkit?name=flag-enable-reconnect-ethers", "ethers reconnect disabled", true),
  scenario("flags", "flag-enable-reconnect-ethers5", "/appkit?name=flag-enable-reconnect-ethers5", "ethers v5 reconnect disabled", true),
  scenario("flags", "flag-exclude-wallet-ids", "/appkit?name=flag-exclude-wallet-ids", "excluded wallet IDs", true),
  scenario("flags", "flag-no-coinbase", "/appkit?name=flag-no-coinbase", "Coinbase disabled", true),
  scenario("verify", "wagmi-verify-valid", "/appkit?name=wagmi-verify-valid", "Verify API happy-path source route", false),
  scenario("verify", "wagmi-verify-domain-mismatch", "/appkit?name=wagmi-verify-domain-mismatch", "Verify API domain mismatch source route", false),
  scenario("verify", "wagmi-verify-evil", "/appkit?name=wagmi-verify-evil", "Verify API malicious-domain source route", false),
  scenario("verify", "ethers-verify-valid", "/appkit?name=ethers-verify-valid", "ethers Verify API happy-path source route", false),
  scenario("verify", "ethers-verify-domain-mismatch", "/appkit?name=ethers-verify-domain-mismatch", "ethers Verify API domain mismatch source route", false),
  scenario("verify", "ethers-verify-evil", "/appkit?name=ethers-verify-evil", "ethers Verify API malicious-domain source route", false),
];

const args = parseArgs(Bun.argv.slice(2));

if (args.command === "routes") {
  await runRoutes(args);
} else if (args.command === "catalog") {
  await runCatalog(args);
} else {
  await runCaptureUri(args);
}

function scenario(
  category: CatalogCategory,
  name: string,
  route: string,
  note: string,
  publicLink: boolean,
  routeKind: RouteKind = "appkit",
  expectation: RouteExpectation = "valid",
): LabScenario {
  return {
    category,
    expectation,
    name,
    note,
    publicLink,
    route,
    routeKind,
  };
}

function parseArgs(argv: string[]): ParsedArgs {
  const command = argv.shift();
  if (!isLabCommand(command)) {
    usage(`unknown or missing lab command: ${String(command)}`);
  }

  const parsed: ParsedArgs = {
    baseUrl: readOption("WC_LAB_BASE_URL") ?? DEFAULT_BASE_URL,
    command,
    headed: false,
    json: false,
    scenario: "wagmi",
    showUri: false,
    timeoutMs: readIntegerOption("WC_LAB_TIMEOUT_MS") ?? DEFAULT_TIMEOUT_MS,
    validate: false,
  };

  while (argv.length > 0) {
    const arg = requiredShift(argv);
    if (arg === "--base-url") {
      parsed.baseUrl = requiredShift(argv);
    } else if (arg === "--headed") {
      parsed.headed = true;
    } else if (arg === "--json") {
      parsed.json = true;
    } else if (arg === "--scenario") {
      parsed.scenario = requiredShift(argv);
    } else if (arg === "--show-uri") {
      parsed.showUri = true;
    } else if (arg === "--timeout-ms") {
      parsed.timeoutMs = parsePositiveInteger(requiredShift(argv), "--timeout-ms");
    } else if (arg === "--validate") {
      parsed.validate = true;
    } else {
      usage(`unknown lab argument: ${arg}`);
    }
  }

  return parsed;
}

function isLabCommand(value: string | undefined): value is LabCommand {
  return value === "routes" || value === "catalog" || value === "capture-uri";
}

function requiredShift(argv: string[]): string {
  const value = argv.shift();
  if (!value) {
    usage("missing argument value");
  }
  return value;
}

function usage(message: string): never {
  console.error(message);
  console.error(
    [
      "usage:",
      "  bun run lab routes [--base-url URL] [--json] [--timeout-ms MS]",
      "  bun run lab catalog [--base-url URL] [--json] [--validate] [--timeout-ms MS]",
      "  bun run lab capture-uri [--base-url URL] [--scenario NAME] [--show-uri] [--headed] [--timeout-ms MS]",
    ].join("\n"),
  );
  process.exit(2);
}

async function runRoutes(args: ParsedArgs): Promise<void> {
  const routeNames = await fetchPublicRouteNames(args);
  const statuses = await validateRoutes(args, routeNames);
  const unexpectedFailures = statuses.filter(
    (status) => !status.ok && status.expectation !== "known-broken",
  );

  printStatuses("lab routes", statuses, args.json);

  if (unexpectedFailures.length > 0) {
    process.exit(1);
  }
}

async function runCatalog(args: ParsedArgs): Promise<void> {
  if (!args.validate) {
    if (args.json) {
      console.log(JSON.stringify({ references: references(), scenarios: LAB_CATALOG }, null, 2));
    } else {
      printCatalog();
    }
    return;
  }

  const statuses = await validateRoutes(
    args,
    LAB_CATALOG.map((entry) => entry.name),
  );
  const unexpectedFailures = statuses.filter(
    (status) => !status.ok && status.expectation !== "known-broken",
  );
  const unexpectedSuccesses = statuses.filter(
    (status) => status.ok && status.expectation === "known-broken",
  );

  printStatuses("lab catalog", statuses, args.json);

  if (unexpectedFailures.length > 0 || unexpectedSuccesses.length > 0) {
    process.exit(1);
  }
}

function printCatalog(): void {
  console.log(`references:`);
  for (const reference of references()) {
    console.log(`  ${reference}`);
  }
  console.log("scenarios:");
  for (const entry of LAB_CATALOG) {
    const publicMarker = entry.publicLink ? "public" : "source";
    console.log(
      `  ${entry.name} category=${entry.category} route=${entry.route} expectation=${entry.expectation} ${publicMarker} note="${entry.note}"`,
    );
  }
}

async function fetchPublicRouteNames(args: ParsedArgs): Promise<string[]> {
  const home = await fetchText(new URL("/", normalizedBaseUrl(args.baseUrl)).toString(), args.timeoutMs);
  const names = new Set<string>();
  const linkPattern = /href="\/appkit\?name=([^"#&]+)"/gu;
  for (const match of home.matchAll(linkPattern)) {
    const name = match[1];
    if (name) {
      names.add(name);
    }
  }

  return [...names].sort();
}

async function validateRoutes(args: ParsedArgs, names: string[]): Promise<RouteStatus[]> {
  const statuses: RouteStatus[] = [];

  let nextIndex = 0;
  const workers = Array.from(
    { length: Math.min(ROUTE_VALIDATION_CONCURRENCY, names.length) },
    async () => {
      while (nextIndex < names.length) {
        const currentIndex = nextIndex;
        nextIndex += 1;

        const name = names[currentIndex];
        if (!name) {
          continue;
        }
        statuses[currentIndex] = await validateRoute(args, name);
      }
    },
  );
  await Promise.all(workers);

  return statuses;
}

async function validateRoute(args: ParsedArgs, name: string): Promise<RouteStatus> {
  const entry = findScenario(name);
  const route = entry?.route ?? `/appkit?name=${encodeURIComponent(name)}`;
  const url = new URL(route, normalizedBaseUrl(args.baseUrl));

  try {
    const response = await fetchWithTimeout(url.toString(), args.timeoutMs);
    const body = await response.text();
    const rendersConfigNotFound = body.includes("Config not found");
    const ok = response.ok && !rendersConfigNotFound;
    return {
      bodyHint: rendersConfigNotFound ? "Config not found" : "",
      expectation: entry?.expectation ?? "valid",
      name,
      ok,
      route,
      status: response.status,
    };
  } catch (error) {
    return {
      bodyHint: error instanceof Error ? error.message : String(error),
      expectation: entry?.expectation ?? "valid",
      name,
      ok: false,
      route,
      status: null,
    };
  }
}

function printStatuses(label: string, statuses: RouteStatus[], json: boolean): void {
  const summary = {
    broken: statuses.filter((status) => !status.ok && status.expectation !== "known-broken")
      .length,
    knownBroken: statuses.filter((status) => !status.ok && status.expectation === "known-broken")
      .length,
    ok: statuses.filter((status) => status.ok).length,
    total: statuses.length,
  };

  if (json) {
    console.log(JSON.stringify({ label, references: references(), statuses, summary }, null, 2));
    return;
  }

  console.log(
    `${label} total=${summary.total} ok=${summary.ok} known_broken=${summary.knownBroken} broken=${summary.broken}`,
  );
  for (const status of statuses) {
    const result = status.ok ? "ok" : status.expectation === "known-broken" ? "known-broken" : "broken";
    const suffix = status.bodyHint ? ` hint="${status.bodyHint}"` : "";
    console.log(`${result} ${status.name} status=${status.status ?? "none"} route=${status.route}${suffix}`);
  }
}

async function runCaptureUri(args: ParsedArgs): Promise<void> {
  const entry = findScenario(args.scenario);
  if (!entry) {
    throw new Error(`unknown lab scenario: ${args.scenario}`);
  }
  if (entry.expectation === "known-broken") {
    throw new Error(`scenario ${entry.name} is marked known-broken: ${entry.note}`);
  }

  let browser: Browser | undefined;
  try {
    browser = await chromium.launch({
      executablePath: findBrowserExecutable(),
      headless: !args.headed,
    });
    const page = await browser.newPage();
    page.on("console", (message) => {
      if (message.type() === "error" || message.type() === "warning") {
        if (message.text().includes("Executing inline script violates")) {
          return;
        }
        console.error(`[browser.${message.type()}] ${message.text()}`);
      }
    });

    const uri =
      entry.routeKind === "core"
        ? await captureCoreSignClientUri(page, args, entry)
        : await captureAppKitUri(page, args, entry);

    if (args.json) {
      console.log(
        JSON.stringify(
          {
            redactedUri: redactUri(uri),
            route: entry.route,
            scenario: entry.name,
            uri: args.showUri ? uri : undefined,
          },
          null,
          2,
        ),
      );
    } else {
      console.log(`lab capture scenario=${entry.name} route=${entry.route}`);
      console.log(`uri_redacted=${redactUri(uri)}`);
      if (args.showUri) {
        console.log(`uri=${uri}`);
      } else {
        console.log("uri=<redacted; pass --show-uri to print full pairing URI>");
      }
    }
  } finally {
    await browser?.close();
  }
}

async function captureAppKitUri(
  page: Page,
  args: ParsedArgs,
  scenarioEntry: LabScenario,
): Promise<string> {
  await page.goto(new URL(scenarioEntry.route, normalizedBaseUrl(args.baseUrl)).toString(), {
    waitUntil: "domcontentloaded",
    timeout: args.timeoutMs,
  });
  await page.locator("w3m-modal").waitFor({ state: "visible", timeout: args.timeoutMs });
  await page.getByTestId("connect-button").first().click({ timeout: args.timeoutMs });
  await page.getByTestId("wallet-selector-walletconnect").click({ timeout: args.timeoutMs });

  return readQrUri(page, args.timeoutMs);
}

async function captureCoreSignClientUri(
  page: Page,
  args: ParsedArgs,
  scenarioEntry: LabScenario,
): Promise<string> {
  await page.goto(new URL(scenarioEntry.route, normalizedBaseUrl(args.baseUrl)).toString(), {
    waitUntil: "domcontentloaded",
    timeout: args.timeoutMs,
  });
  await page.getByTestId("connect-button").click({ timeout: args.timeoutMs });

  return readQrUri(page, args.timeoutMs);
}

async function readQrUri(page: Page, timeoutMs: number): Promise<string> {
  const qrCode = page.locator("wui-qr-code");
  await qrCode.waitFor({ state: "attached", timeout: timeoutMs });

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const uri = await qrCode.getAttribute("uri", { timeout: 1_000 }).catch(() => null);
    if (uri) {
      return uri;
    }
    await page.waitForTimeout(250);
  }

  throw new Error("QR code did not expose a WalletConnect URI");
}

function findScenario(name: string): LabScenario | undefined {
  return LAB_CATALOG.find((entry) => entry.name === name);
}

async function fetchText(url: string, timeoutMs: number): Promise<string> {
  const response = await fetchWithTimeout(url, timeoutMs);
  if (!response.ok) {
    throw new Error(`request failed status=${response.status} url=${url}`);
  }
  return response.text();
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const abortController = new AbortController();
  const timeout = setTimeout(() => abortController.abort(), timeoutMs);
  try {
    return await fetch(url, { signal: abortController.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function normalizedBaseUrl(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
}

function readOption(name: string): string | undefined {
  const value = process.env[name];
  return value && value.length > 0 ? value : undefined;
}

function readIntegerOption(name: string): number | undefined {
  const value = readOption(name);
  if (!value) {
    return undefined;
  }
  return parsePositiveInteger(value, name);
}

function parsePositiveInteger(value: string, label: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    usage(`${label} must be a positive integer`);
  }
  return parsed;
}

function references(): string[] {
  return [
    LAB_HOME_REFERENCE,
    LAB_CONFIG_REFERENCE,
    LAB_APPKIT_ROUTE_REFERENCE,
    LAB_SIGN_CLIENT_REFERENCE,
  ];
}

function findBrowserExecutable(): string {
  const explicit = readOption("WC_LAB_BROWSER");
  if (explicit) {
    return explicit;
  }

  const candidates = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ];

  const candidate = candidates.find((path) => existsSync(path));
  if (!candidate) {
    throw new Error("no Chromium-compatible browser found; set WC_LAB_BROWSER");
  }

  return candidate;
}

function redactUri(uri: string): string {
  const symKeyIndex = uri.indexOf("symKey=");
  if (symKeyIndex < 0) {
    return uri.length <= 24 ? "<redacted>" : `${uri.slice(0, 12)}...${uri.slice(-8)}`;
  }

  const prefix = uri.slice(0, symKeyIndex + "symKey=".length);
  return `${prefix}<redacted>`;
}
