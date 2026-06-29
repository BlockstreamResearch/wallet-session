import { createHash } from "node:crypto";
import { AUTH_PUBLIC_KEY_NAME, SignClient } from "@walletconnect/sign-client";
import {
  calcExpiry,
  createEncodedRecap,
  engineEvent,
  getRecapFromResources,
  hashKey,
  mergeEncodedRecaps,
  parseChainId,
} from "@walletconnect/utils";

const projectId = process.env.REOWN_PROJECT_ID ?? process.env.WALLETCONNECT_PROJECT_ID;

if (!projectId) {
  console.error("set REOWN_PROJECT_ID or WALLETCONNECT_PROJECT_ID");
  process.exit(1);
}

const relayUrl = process.env.REOWN_RELAY_URL ?? "wss://relay.walletconnect.com";
const holdMs = readIntEnv("WC_JS_HARNESS_HOLD_MS", 120_000);
const uriFile = process.env.WC_JS_URI_FILE;
const resultFile = process.env.WC_JS_RESULT_FILE;
const printUri = process.env.WC_JS_PRINT_URI === "1";
const logDecryptedPayloads = matchesEnvFlag(process.env.WC_JS_LOG_DECRYPTED_PAYLOADS);
const chains = envList("WC_JS_AUTH_CHAINS", ["bip122:000000000933ea01ad0ee984209779ba"]);
const methods = envList("WC_JS_AUTH_METHODS", []);
const storageSuffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
const sensitiveKeys = new Set([
  "accounts",
  "address",
  "auths",
  "authentication",
  "cacao",
  "cacaos",
  "data",
  "iss",
  "metadata",
  "params",
  "peer",
  "publicKey",
  "request",
  "responder",
  "result",
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
  customStoragePrefix: `wc-bitcoin-auth-dapp-${storageSuffix}`,
  metadata: {
    name: process.env.WC_JS_METADATA_NAME ?? "walletconnect-client-poc Bitcoin auth harness",
    description: "Live Bitcoin WalletConnect authentication generator",
    url: process.env.WC_JS_METADATA_URL ?? "https://lab.reown.com",
    icons: ["https://walletconnect.com/walletconnect-logo.png"],
  },
});

type EngineInternal = {
  events: {
    once(event: string, listener: (payload: AuthEventPayload) => void): void;
  };
  sendRequest(args: {
    topic: string;
    method: "wc_sessionAuthenticate";
    params: SessionAuthenticateRequestParams;
    expiry?: number;
    throwOnFailedPublish?: boolean;
    clientRpcId?: number;
  }): Promise<number | string>;
};

type AuthEventPayload = {
  error?: { code?: number; message?: string };
  result?: unknown;
};

type SessionAuthenticateRequestParams = {
  authPayload: {
    type: string;
    chains: string[];
    statement?: string;
    aud: string;
    domain: string;
    version: string;
    nonce: string;
    iat: string;
    exp?: string;
    nbf?: string;
    requestId?: string;
    resources?: string[];
  };
  requester: {
    publicKey: string;
    metadata: typeof signClient.metadata;
  };
  expiryTimestamp: number;
};

let timeout: Timer | undefined;

try {
  const { topic: pairingTopic, uri } = await signClient.core.pairing.create({
    methods: ["wc_sessionAuthenticate"],
  });

  if (!uri) {
    throw new Error("sign-client did not return an authentication pairing URI");
  }

  const publicKey = await signClient.core.crypto.generateKeyPair();
  const responseTopic = hashKey(publicKey);

  await Promise.all([
    signClient.auth.authKeys.set(AUTH_PUBLIC_KEY_NAME, { responseTopic, publicKey }),
    signClient.auth.pairingTopics.set(responseTopic, { topic: responseTopic, pairingTopic }),
    signClient.core.relayer.subscribe(responseTopic),
  ]);

  const resources = authResources(chains, methods);
  const requestTtl = Math.max(readIntEnv("WC_JS_AUTH_EXPIRY", 3_600), 3_600);
  const authPayload: SessionAuthenticateRequestParams["authPayload"] = {
    type: process.env.WC_JS_AUTH_TYPE ?? "caip122",
    chains,
    statement: process.env.WC_JS_AUTH_STATEMENT ?? "Sign in to Reown Bitcoin Testnet",
    aud: process.env.WC_JS_AUTH_URI ?? "https://lab.reown.com/login",
    domain: process.env.WC_JS_AUTH_DOMAIN ?? "lab.reown.com",
    version: "1",
    nonce: process.env.WC_JS_AUTH_NONCE ?? "1234567890",
    iat: new Date().toISOString(),
  };
  if (process.env.WC_JS_AUTH_EXP) {
    authPayload.exp = process.env.WC_JS_AUTH_EXP;
  }
  if (process.env.WC_JS_AUTH_NBF) {
    authPayload.nbf = process.env.WC_JS_AUTH_NBF;
  }
  if (process.env.WC_JS_AUTH_REQUEST_ID) {
    authPayload.requestId = process.env.WC_JS_AUTH_REQUEST_ID;
  }
  if (resources) {
    authPayload.resources = resources;
  }

  const request: SessionAuthenticateRequestParams = {
    authPayload,
    requester: {
      publicKey,
      metadata: signClient.metadata,
    },
    expiryTimestamp: calcExpiry(requestTtl),
  };

  if (uriFile) {
    await Bun.write(uriFile, `${uri}\n`);
  }

  if (printUri) {
    console.log(`WC_PAIRING_URI=${uri}`);
  }

  if (uriFile) {
    console.log(`WC_PAIRING_URI_FILE=${uriFile}`);
  }

  console.error(
    `js-harness bitcoin_authenticate_uri_ready=true hold_ms=${holdMs} chain_ids=${chains.join(",")} uri=${redactPairingUri(uri)}`,
  );

  const engine = signClient.engine as unknown as EngineInternal;
  const authenticateId = randomRpcId();
  const eventTarget = engineEvent("session_request", authenticateId);
  const responsePromise = new Promise<AuthEventPayload>((resolve) => {
    engine.events.once(eventTarget, resolve);
  });

  await engine.sendRequest({
    topic: pairingTopic,
    method: "wc_sessionAuthenticate",
    params: request,
    expiry: requestTtl,
    throwOnFailedPublish: true,
    clientRpcId: authenticateId,
  });

  const result = await Promise.race([
    responsePromise,
    sleep(holdMs).then(() => null),
  ]);

  if (result?.result) {
    const summary = authenticateResultSummary(result.result);
    console.error(`js-harness bitcoin_authenticate_response=${JSON.stringify(summary)}`);
    await writeResult({
      outcome: "bitcoin_authenticate_response",
      request: requestSummary(request, authenticateId, pairingTopic, responseTopic),
      result: result.result,
    });
  } else if (result?.error) {
    console.error(`js-harness bitcoin_authenticate_error=${errorMessage(result.error)}`);
    await writeResult({
      outcome: "bitcoin_authenticate_error",
      request: requestSummary(request, authenticateId, pairingTopic, responseTopic),
      error: result.error,
    });
  } else {
    console.error("js-harness bitcoin_authenticate_timeout=true");
    await writeResult({
      outcome: "bitcoin_authenticate_timeout",
      request: requestSummary(request, authenticateId, pairingTopic, responseTopic),
    });
  }

} catch (error) {
  const message = errorMessage(error);
  console.error(`js-harness bitcoin_authenticate_harness_error=${message}`);
  await writeResult({
    outcome: "bitcoin_authenticate_harness_error",
    message,
  });
  process.exitCode = 1;
} finally {
  if (timeout) {
    clearTimeout(timeout);
  }
  await closeRelay();
  process.exit(typeof process.exitCode === "number" ? process.exitCode : 0);
}

function authResources(chainIds: string[], requestedMethods: string[]): string[] | undefined {
  const configured = envList("WC_JS_AUTH_RESOURCES", []);
  const resources = [...configured];
  if (requestedMethods.length === 0) {
    return resources.length > 0 ? resources : undefined;
  }

  const firstChain = chainIds[0];
  if (!firstChain) {
    throw new Error("WC_JS_AUTH_CHAINS must contain at least one chain");
  }
  const { namespace } = parseChainId(firstChain);
  let recap = createEncodedRecap(namespace, "request", requestedMethods);
  const existingRecap = getRecapFromResources(resources);
  if (existingRecap) {
    recap = mergeEncodedRecaps(recap, resources.pop() as string);
  }
  resources.push(recap);
  return resources;
}

function envList(name: string, fallback: string[]): string[] {
  const value = process.env[name];
  if (!value) {
    return fallback;
  }

  const values = value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (values.length === 0 && fallback.length > 0) {
    throw new Error(`${name} must contain at least one comma-separated value`);
  }
  return values;
}

function randomRpcId(): number {
  const value = Number.parseInt(
    `${Date.now()}${Math.floor(Math.random() * 1_000_000).toString().padStart(6, "0")}`,
    10,
  );
  return Number.isSafeInteger(value) ? value : Math.floor(Date.now() + Math.random() * 1_000_000);
}

function readIntEnv(name: string, fallback: number): number {
  const value = process.env[name];
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function sleep(milliseconds: number): Promise<null> {
  return new Promise((resolve) => {
    timeout = setTimeout(() => resolve(null), milliseconds);
  });
}

async function closeRelay(): Promise<void> {
  const closeTimeoutMs = 2_000;
  await Promise.race([
    signClient.core.relayer.transportClose().catch((error) => {
      console.error(`js-harness relay_close_error=${errorMessage(error)}`);
    }),
    new Promise<void>((resolve) => {
      setTimeout(resolve, closeTimeoutMs);
    }),
  ]);
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

function requestSummary(
  request: SessionAuthenticateRequestParams,
  id: number,
  pairingTopic: string,
  responseTopic: string,
): Record<string, unknown> {
  return {
    id,
    pairingTopic,
    responseTopic,
    chains: request.authPayload.chains,
    domain: request.authPayload.domain,
    aud: request.authPayload.aud,
    statement: request.authPayload.statement,
    nonce: request.authPayload.nonce,
    resourcesCount: request.authPayload.resources?.length ?? 0,
  };
}

function authenticateResultSummary(result: unknown): Record<string, unknown> {
  const normalized = normalizeJson(result);
  const object =
    normalized && typeof normalized === "object" && !Array.isArray(normalized)
      ? (normalized as Record<string, unknown>)
      : {};
  const cacaos = Array.isArray(object.cacaos) ? object.cacaos : [];
  const responder =
    object.responder && typeof object.responder === "object" && !Array.isArray(object.responder)
      ? (object.responder as Record<string, unknown>)
      : undefined;

  return {
    cacaosCount: cacaos.length,
    responder: responder
      ? {
          metadataName:
            responder.metadata &&
            typeof responder.metadata === "object" &&
            !Array.isArray(responder.metadata)
              ? (responder.metadata as Record<string, unknown>).name
              : undefined,
          publicKey: redactedSummary(responder.publicKey),
        }
      : undefined,
  };
}

function resultForFile(result: Record<string, unknown>): unknown {
  const normalized = normalizeJson(result) as Record<string, unknown>;
  if (logDecryptedPayloads) {
    return normalized;
  }
  return redactHarnessValue(normalized);
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
    return value.map((entry) => normalizeJson(entry));
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
  if (Array.isArray(value)) {
    return "array";
  }
  if (value === null) {
    return "null";
  }
  return typeof value;
}

function matchesEnvFlag(value: string | undefined): boolean {
  if (!value) {
    return false;
  }
  return ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
}
