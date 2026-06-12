import { createHash } from "node:crypto";
import { SignClient } from "@walletconnect/sign-client";

const projectId = process.env.REOWN_PROJECT_ID ?? process.env.WALLETCONNECT_PROJECT_ID;

if (!projectId) {
  console.error("set REOWN_PROJECT_ID or WALLETCONNECT_PROJECT_ID");
  process.exit(1);
}

const relayUrl = process.env.REOWN_RELAY_URL ?? "wss://relay.walletconnect.com";
const holdMs = Number.parseInt(process.env.WC_JS_HARNESS_HOLD_MS ?? "120000", 10);
const uriFile = process.env.WC_JS_URI_FILE;
const resultFile = process.env.WC_JS_RESULT_FILE;
const printUri = process.env.WC_JS_PRINT_URI === "1";
const logDecryptedPayloads = matchesEnvFlag(process.env.WC_JS_LOG_DECRYPTED_PAYLOADS);
const sensitiveKeys = new Set([
  "accounts",
  "address",
  "auths",
  "authentication",
  "cacao",
  "cacaos",
  "data",
  "iss",
  "namespaces",
  "params",
  "request",
  "s",
  "signature",
  "signatures",
]);

if (!uriFile && !printUri) {
  console.error("set WC_JS_URI_FILE or set WC_JS_PRINT_URI=1 to print the full pairing URI");
  process.exit(1);
}

const signClient = await SignClient.init({
  projectId,
  relayUrl,
  metadata: {
    name: "walletconnect-client-poc JS auth harness",
    description: "Live WalletConnect authentication generator for Rust probes",
    url: "https://github.com/BlockstreamResearch/walletconnect-client-poc",
    icons: ["https://walletconnect.com/walletconnect-logo.png"],
  },
});

const { uri, response } = await signClient.authenticate({
  domain: process.env.WC_JS_AUTH_DOMAIN ?? "example.com",
  chains: (process.env.WC_JS_AUTH_CHAINS ?? "eip155:1").split(",").filter(Boolean),
  nonce: process.env.WC_JS_AUTH_NONCE ?? "1234567890",
  uri: process.env.WC_JS_AUTH_URI ?? "https://example.com/login",
  methods: (process.env.WC_JS_AUTH_METHODS ?? "personal_sign").split(",").filter(Boolean),
  statement: process.env.WC_JS_AUTH_STATEMENT ?? "Sign in to Example",
});

if (!uri) {
  console.error("sign-client did not return an authentication pairing URI");
  process.exit(1);
}

if (uriFile) {
  await Bun.write(uriFile, `${uri}\n`);
}

if (printUri) {
  console.log(`WC_PAIRING_URI=${uri}`);
}

if (uriFile) {
  console.log(`WC_PAIRING_URI_FILE=${uriFile}`);
}

console.error(`js-harness authenticate_uri_ready=true hold_ms=${holdMs} uri=${redactPairingUri(uri)}`);

let timeout: Timer | undefined;

try {
  const timeoutPromise = new Promise<null>((resolve) => {
    timeout = setTimeout(() => resolve(null), holdMs);
  });
  const result = await Promise.race([response(), timeoutPromise]);

  if (result) {
    console.error(`js-harness authenticate_response=${stringifyForLog(result)}`);
    await writeResult({
      outcome: "authenticate_response",
      result,
    });
  } else {
    console.error("js-harness authenticate_timeout=true");
    await writeResult({
      outcome: "authenticate_timeout",
    });
  }
} catch (error) {
  const message = errorMessage(error);
  console.error(`js-harness authenticate_error=${message}`);
  await writeResult({
    outcome: "authenticate_error",
    message,
  });
} finally {
  if (timeout) {
    clearTimeout(timeout);
  }

  await signClient.core.relayer.transportClose();
}

function redactPairingUri(uri: string): string {
  return uri.replace(/([?&]symKey=)[^&]+/, "$1<redacted>");
}

async function writeResult(result: Record<string, unknown>): Promise<void> {
  if (!resultFile) {
    return;
  }
  await Bun.write(resultFile, JSON.stringify(resultForFile(result), null, 2));
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return stringForLog(error.message);
  }
  if (typeof error === "object" && error !== null) {
    return stringifyForLog(error);
  }
  return stringForLog(String(error));
}

function stringForLog(value: string): string {
  try {
    return stringifyForLog(JSON.parse(value) as unknown);
  } catch {
    return value;
  }
}

function stringifyForLog(value: unknown): string {
  return JSON.stringify(valueForLog(value));
}

function resultForFile(result: Record<string, unknown>): unknown {
  const normalized = normalizeJson(result) as Record<string, unknown>;
  if (logDecryptedPayloads) {
    return normalized;
  }

  if (normalized.outcome === "authenticate_response" && normalized.result) {
    return {
      ...normalized,
      result: authenticateResultSummary(normalized.result),
    };
  }

  return redactHarnessValue(normalized);
}

function authenticateResultSummary(result: unknown): Record<string, unknown> {
  const normalized = normalizeJson(result);
  const object =
    normalized && typeof normalized === "object" && !Array.isArray(normalized)
      ? (normalized as Record<string, unknown>)
      : {};
  const session =
    object.session && typeof object.session === "object" && !Array.isArray(object.session)
      ? (object.session as Record<string, unknown>)
      : undefined;
  const namespaces =
    session?.namespaces && typeof session.namespaces === "object" && !Array.isArray(session.namespaces)
      ? (session.namespaces as Record<string, unknown>)
      : undefined;

  return {
    ...redactedSummary(normalized),
    session: session
      ? {
          topic: session.topic,
          acknowledged: session.acknowledged,
          expiry: session.expiry,
          namespacesCount: namespaces ? Object.keys(namespaces).length : undefined,
        }
      : undefined,
  };
}

function valueForLog(value: unknown): unknown {
  const normalized = normalizeJson(value);
  return logDecryptedPayloads ? normalized : redactHarnessValue(normalized);
}

function redactHarnessValue(value: unknown, key?: string): unknown {
  if (key && sensitiveKeys.has(key)) {
    return redactedSummary(value);
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactHarnessValue(item));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([entryKey, entryValue]) => [
        entryKey,
        redactHarnessValue(entryValue, entryKey),
      ]),
    );
  }

  return value;
}

function redactedSummary(value: unknown): Record<string, unknown> {
  const normalized = normalizeJson(value);
  const text = JSON.stringify(normalized);
  const summary: Record<string, unknown> = {
    redacted: true,
    type: valueKind(normalized),
    hash: createHash("sha256").update(text).digest("hex"),
  };

  if (typeof normalized === "string") {
    summary.len = normalized.length;
  } else if (Array.isArray(normalized)) {
    summary.len = normalized.length;
  } else if (normalized && typeof normalized === "object") {
    const keys = Object.keys(normalized as Record<string, unknown>);
    summary.keys = keys;
    summary.len = keys.length;
  }

  return summary;
}

function normalizeJson(value: unknown): unknown {
  if (typeof value === "bigint") {
    return value.toString();
  }

  if (Array.isArray(value)) {
    return value.map((item) => normalizeJson(item));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([entryKey, entryValue]) => [
        entryKey,
        normalizeJson(entryValue),
      ]),
    );
  }

  return value;
}

function valueKind(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "array";
  }
  return typeof value;
}

function matchesEnvFlag(value: string | undefined): boolean {
  return value === "1" || value === "true" || value === "yes";
}
