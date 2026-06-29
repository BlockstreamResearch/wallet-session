import { createHash } from "node:crypto";
import { SignClient } from "@walletconnect/sign-client";

const projectId = process.env.REOWN_PROJECT_ID ?? process.env.WALLETCONNECT_PROJECT_ID;

if (!projectId) {
  console.error("set REOWN_PROJECT_ID or WALLETCONNECT_PROJECT_ID");
  process.exit(1);
}

const relayUrl = process.env.REOWN_RELAY_URL ?? "wss://relay.walletconnect.com";
const holdMs = Number.parseInt(process.env.WC_JS_HARNESS_HOLD_MS ?? "120000", 10);
const sessionRequestHoldMs = Number.parseInt(
  process.env.WC_JS_SESSION_REQUEST_HOLD_MS ?? String(holdMs),
  10,
);
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
  "metadata",
  "namespaces",
  "params",
  "peer",
  "publicKey",
  "request",
  "result",
  "self",
  "s",
  "signature",
  "signatures",
]);
const sendSessionRequest = process.env.WC_JS_SEND_SESSION_REQUEST === "1";
const afterApprovalAction =
  process.env.WC_JS_AFTER_APPROVAL_ACTION ?? (sendSessionRequest ? "session_request" : "approved");
const waitForSessionRequestResponse =
  process.env.WC_JS_SESSION_REQUEST_WAIT_FOR_RESPONSE === "1";
const proposalChains = envList("WC_JS_PROPOSAL_CHAINS", ["eip155:1"]);
const proposalNamespace = process.env.WC_JS_PROPOSAL_NAMESPACE ?? "eip155";
const proposalMethods = envList("WC_JS_PROPOSAL_METHODS", [
  "personal_sign",
  "eth_signTypedData_v4",
]);
const proposalEvents = envList("WC_JS_PROPOSAL_EVENTS", [
  "accountsChanged",
  "chainChanged",
]);
const metadataRedirect = jsonEnv("WC_JS_METADATA_REDIRECT_JSON") as
  | MetadataRedirect
  | undefined;

if (!uriFile && !printUri) {
  console.error("set WC_JS_URI_FILE or set WC_JS_PRINT_URI=1 to print the full pairing URI");
  process.exit(1);
}

const signClient = await SignClient.init({
  projectId,
  relayUrl,
  metadata: {
    name: process.env.WC_JS_METADATA_NAME ?? "walletconnect-client-poc JS harness",
    description: "Live WalletConnect proposal generator for Rust protocol probes",
    url:
      process.env.WC_JS_METADATA_URL ??
      "https://github.com/BlockstreamResearch/walletconnect-client-poc",
    icons: ["https://walletconnect.com/walletconnect-logo.png"],
    ...(metadataRedirect ? { redirect: metadataRedirect } : {}),
  },
});

type ConnectParams = Parameters<typeof signClient.connect>[0];

const sessionProperties = jsonEnv("WC_JS_SESSION_PROPERTIES_JSON") as
  | ConnectParams["sessionProperties"]
  | undefined;
const scopedProperties = jsonEnv("WC_JS_SCOPED_PROPERTIES_JSON") as
  | ConnectParams["scopedProperties"]
  | undefined;
const connectParams: ConnectParams = {
  requiredNamespaces: {
    [proposalNamespace]: {
      chains: proposalChains,
      methods: proposalMethods,
      events: proposalEvents,
    },
  },
};
if (sessionProperties) {
  connectParams.sessionProperties = sessionProperties;
}
if (scopedProperties) {
  connectParams.scopedProperties = scopedProperties;
}

const { uri, approval } = await signClient.connect(connectParams);

if (!uri) {
  console.error("sign-client did not return a pairing URI");
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

console.error(`js-harness proposal_uri_ready=true hold_ms=${holdMs} uri=${redactPairingUri(uri)}`);

let timeout: Timer | undefined;

try {
  const timeoutPromise = new Promise<null>((resolve) => {
    timeout = setTimeout(() => resolve(null), holdMs);
  });
  const session = await Promise.race([approval(), timeoutPromise]);

  if (session) {
    console.error(`js-harness approved_session_topic=${session.topic}`);
    if (matchesEnvFlag(process.env.WC_JS_LOG_SESSION_NAMESPACES)) {
      console.error(`js-harness approved_session_namespaces=${stringifyForLog(session.namespaces)}`);
    }
    switch (afterApprovalAction) {
      case "approved":
        await writeResult({
          outcome: "approved",
          topic: session.topic,
        });
        break;
      case "session_request":
        await startSessionRequest(session.topic, session.namespaces);
        break;
      case "session_ping":
        await startSessionPing(session.topic);
        break;
      case "session_delete":
        await startSessionDelete(session.topic);
        break;
      case "session_update":
        await startSessionUpdate(session.topic, session.namespaces);
        break;
      case "session_update_add_permissions":
        await startSessionUpdate(session.topic, sessionUpdateAddPermissions(session.namespaces));
        break;
      case "session_extend":
        await startSessionExtend(session.topic);
        break;
      case "session_event":
        await startSessionEvent(session.topic);
        break;
      case "wait_session_update":
        await waitForSessionUpdate(session.topic);
        break;
      case "wait_session_extend":
        await waitForSessionExtend(session.topic);
        break;
      case "wait_session_event":
        await waitForSessionEvent(session.topic);
        break;
      case "wait_session_delete":
        await waitForSessionDelete(session.topic);
        break;
      default:
        throw new Error(`unknown WC_JS_AFTER_APPROVAL_ACTION=${afterApprovalAction}`);
    }
  } else {
    console.error("js-harness proposal_timeout=true");
    await writeResult({
      outcome: "timeout",
    });
  }
} catch (error) {
  const message = errorMessage(error);
  console.error(`js-harness approval_error=${message}`);
  await writeResult({
    outcome: "approval_error",
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

function envList(name: string, fallback: string[]): string[] {
  const value = process.env[name];
  if (!value) {
    return fallback;
  }

  const values = value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (values.length === 0) {
    throw new Error(`${name} must contain at least one comma-separated value`);
  }

  return values;
}

function jsonEnv(name: string): unknown | undefined {
  const value = process.env[name];
  if (!value) {
    return undefined;
  }

  return JSON.parse(value) as unknown;
}

type MetadataRedirect = {
  native?: string;
  universal?: string;
  linkMode?: boolean;
};

async function writeResult(result: Record<string, unknown>): Promise<void> {
  if (!resultFile) {
    return;
  }

  await Bun.write(resultFile, `${JSON.stringify(valueForLog(result))}\n`);
}

async function startSessionPing(topic: string): Promise<void> {
  const request = signClient.ping({ topic });
  console.error(`js-harness session_ping_started=true topic=${topic} hold_ms=${sessionRequestHoldMs}`);

  const response = await Promise.race([
    request.then(
      () => {
        console.error("js-harness session_ping_response=true");
        return {
          outcome: "session_ping_response",
          topic,
        };
      },
      (error) => {
        const message = errorMessage(error);
        console.error(`js-harness session_ping_error=${message}`);
        return {
          outcome: "session_ping_error",
          topic,
          message,
        };
      },
    ),
    sleep(sessionRequestHoldMs).then(() => ({
      outcome: "session_ping_timeout",
      topic,
    })),
  ]);
  await writeResult(response);
}

async function startSessionDelete(topic: string): Promise<void> {
  const reason = {
    code: Number.parseInt(process.env.WC_JS_SESSION_DELETE_REASON_CODE ?? "6000", 10),
    message: process.env.WC_JS_SESSION_DELETE_REASON_MESSAGE ?? "User disconnected.",
  };
  const request = signClient.disconnect({ topic, reason });
  console.error(
    `js-harness session_delete_started=true topic=${topic} code=${reason.code} message=${JSON.stringify(reason.message)}`,
  );

  const response = await Promise.race([
    request.then(
      () => {
        console.error("js-harness session_delete_sent=true");
        return {
          outcome: "session_delete_sent",
          topic,
          code: reason.code,
          message: reason.message,
        };
      },
      (error) => {
        const message = errorMessage(error);
        console.error(`js-harness session_delete_error=${message}`);
        return {
          outcome: "session_delete_error",
          topic,
          message,
        };
      },
    ),
    sleep(sessionRequestHoldMs).then(() => ({
      outcome: "session_delete_timeout",
      topic,
    })),
  ]);
  await writeResult(response);
}

async function startSessionUpdate(
  topic: string,
  namespaces: Parameters<typeof signClient.update>[0]["namespaces"],
): Promise<void> {
  const request = await signClient.update({ topic, namespaces });
  console.error(`js-harness session_update_started=true topic=${topic} hold_ms=${sessionRequestHoldMs}`);

  const response = await Promise.race([
    request.acknowledged().then(
      () => {
        console.error("js-harness session_update_acknowledged=true");
        return {
          outcome: "session_update_acknowledged",
          topic,
        };
      },
      (error: unknown) => {
        const message = errorMessage(error);
        console.error(`js-harness session_update_error=${message}`);
        return {
          outcome: "session_update_error",
          topic,
          message,
        };
      },
    ),
    sleep(sessionRequestHoldMs).then(() => ({
      outcome: "session_update_timeout",
      topic,
    })),
  ]);
  await writeResult(response);
}

function sessionUpdateAddPermissions(
  namespaces: Parameters<typeof signClient.update>[0]["namespaces"],
): Parameters<typeof signClient.update>[0]["namespaces"] {
  const next = cloneNamespaces(namespaces);
  const eip155 = next.eip155 ?? {
    chains: [],
    accounts: [],
    methods: [],
    events: [],
  };

  eip155.chains = addUnique(eip155.chains ?? [], "eip155:137");
  eip155.accounts = addUnique(
    eip155.accounts,
    "eip155:137:0x3333333333333333333333333333333333333333",
  );
  eip155.methods = addUnique(eip155.methods, "eth_sendTransaction");
  eip155.events = addUnique(eip155.events, "sessionChanged");
  next.eip155 = eip155;

  return next;
}

function cloneNamespaces(
  namespaces: Parameters<typeof signClient.update>[0]["namespaces"],
): Parameters<typeof signClient.update>[0]["namespaces"] {
  return JSON.parse(JSON.stringify(namespaces)) as Parameters<
    typeof signClient.update
  >[0]["namespaces"];
}

function addUnique<T>(values: T[], value: T): T[] {
  return values.includes(value) ? values : [...values, value];
}

async function startSessionExtend(topic: string): Promise<void> {
  const request = await signClient.extend({ topic });
  console.error(`js-harness session_extend_started=true topic=${topic} hold_ms=${sessionRequestHoldMs}`);

  const response = await Promise.race([
    request.acknowledged().then(
      () => {
        console.error("js-harness session_extend_acknowledged=true");
        return {
          outcome: "session_extend_acknowledged",
          topic,
        };
      },
      (error: unknown) => {
        const message = errorMessage(error);
        console.error(`js-harness session_extend_error=${message}`);
        return {
          outcome: "session_extend_error",
          topic,
          message,
        };
      },
    ),
    sleep(sessionRequestHoldMs).then(() => ({
      outcome: "session_extend_timeout",
      topic,
    })),
  ]);
  await writeResult(response);
}

async function startSessionEvent(topic: string): Promise<void> {
  const chainId = process.env.WC_JS_SESSION_EVENT_CHAIN_ID ?? "eip155:1";
  const eventName = process.env.WC_JS_SESSION_EVENT_NAME ?? "accountsChanged";
  const eventData = sessionEventData();
  const request = signClient.emit({
    topic,
    chainId,
    event: {
      name: eventName,
      data: eventData,
    },
  });
  console.error(
    `js-harness session_event_started=true topic=${topic} chain_id=${chainId} event_name=${eventName} hold_ms=${sessionRequestHoldMs}`,
  );

  const response = await Promise.race([
    request.then(
      () => {
        console.error("js-harness session_event_sent=true");
        return {
          outcome: "session_event_sent",
          topic,
          chainId,
          eventName,
        };
      },
      (error: unknown) => {
        const message = errorMessage(error);
        console.error(`js-harness session_event_error=${message}`);
        return {
          outcome: "session_event_error",
          topic,
          chainId,
          eventName,
          message,
        };
      },
    ),
    sleep(sessionRequestHoldMs).then(() => ({
      outcome: "session_event_timeout",
      topic,
      chainId,
      eventName,
    })),
  ]);
  await writeResult(response);
}

async function startSessionRequest(topic: string, namespaces: unknown): Promise<void> {
  const chainId = process.env.WC_JS_SESSION_REQUEST_CHAIN_ID ?? "eip155:1";
  const method = process.env.WC_JS_SESSION_REQUEST_METHOD ?? "personal_sign";
  const expiry = Number.parseInt(process.env.WC_JS_SESSION_REQUEST_EXPIRY ?? "300", 10);
  const params = sessionRequestParams(namespaces);

  const request = signClient.request({
    topic,
    chainId,
    request: {
      method,
      params,
    },
    expiry,
  });

  console.error(
    `js-harness session_request_started=true topic=${topic} chain_id=${chainId} method=${method} hold_ms=${sessionRequestHoldMs}`,
  );

  if (waitForSessionRequestResponse) {
    const response = await Promise.race([
      request.then(
        (result) => {
          console.error(`js-harness session_request_response=${sessionRequestResultForLog(result)}`);
          return {
            outcome: "session_request_response",
            topic,
            chainId,
            method,
            result,
          };
        },
        (error) => {
          const message = errorMessage(error);
          console.error(`js-harness session_request_error=${message}`);
          return {
            outcome: "session_request_error",
            topic,
            chainId,
            method,
            message,
          };
        },
      ),
      sleep(sessionRequestHoldMs).then(() => ({
        outcome: "session_request_timeout",
        topic,
        chainId,
        method,
      })),
    ]);
    await writeResult(response);
    return;
  }

  void request
    .then(async (result) => {
      console.error(`js-harness session_request_response=${sessionRequestResultForLog(result)}`);
      await writeResult({
        outcome: "session_request_response",
        topic,
        chainId,
        method,
        result,
      });
    })
    .catch(async (error) => {
      const message = errorMessage(error);
      console.error(`js-harness session_request_error=${message}`);
      await writeResult({
        outcome: "session_request_error",
        topic,
        chainId,
        method,
        message,
      });
    });

  await writeResult({
    outcome: "session_request_started",
    topic,
    chainId,
    method,
  });
  await sleep(sessionRequestHoldMs);
}

async function waitForSessionUpdate(topic: string): Promise<void> {
  console.error(`js-harness wait_session_update_started=true topic=${topic} hold_ms=${sessionRequestHoldMs}`);
  const response = await Promise.race([
    onceSignClientEvent("session_update", topic).then((event) => {
      console.error(`js-harness session_update_received=${stringifyForLog(event)}`);
      return {
        outcome: "session_update_received",
        topic,
        id: stringifyId(event.id),
      };
    }),
    sleep(sessionRequestHoldMs).then(() => ({
      outcome: "session_update_timeout",
      topic,
    })),
  ]);
  await writeResult(response);
}

async function waitForSessionExtend(topic: string): Promise<void> {
  console.error(`js-harness wait_session_extend_started=true topic=${topic} hold_ms=${sessionRequestHoldMs}`);
  const response = await Promise.race([
    onceSignClientEvent("session_extend", topic).then((event) => {
      console.error(`js-harness session_extend_received=${stringifyForLog(event)}`);
      return {
        outcome: "session_extend_received",
        topic,
        id: stringifyId(event.id),
      };
    }),
    sleep(sessionRequestHoldMs).then(() => ({
      outcome: "session_extend_timeout",
      topic,
    })),
  ]);
  await writeResult(response);
}

async function waitForSessionEvent(topic: string): Promise<void> {
  console.error(`js-harness wait_session_event_started=true topic=${topic} hold_ms=${sessionRequestHoldMs}`);
  const response = await Promise.race([
    onceSignClientEvent("session_event", topic).then((event) => {
      const params = event.params as
        | {
            chainId?: string;
            event?: {
              name?: string;
            };
          }
        | undefined;
      console.error(`js-harness session_event_received=${stringifyForLog(event)}`);
      return {
        outcome: "session_event_received",
        topic,
        id: stringifyId(event.id),
        chainId: params?.chainId,
        eventName: params?.event?.name,
      };
    }),
    sleep(sessionRequestHoldMs).then(() => ({
      outcome: "session_event_timeout",
      topic,
    })),
  ]);
  await writeResult(response);
}

async function waitForSessionDelete(topic: string): Promise<void> {
  console.error(`js-harness wait_session_delete_started=true topic=${topic} hold_ms=${sessionRequestHoldMs}`);
  const response = await Promise.race([
    onceSignClientEvent("session_delete", topic).then((event) => {
      const params = event.params as
        | {
            code?: number;
            message?: string;
          }
        | undefined;
      console.error(`js-harness session_delete_received=${stringifyForLog(event)}`);
      return {
        outcome: "session_delete_received",
        topic,
        id: stringifyId(event.id),
        code: params?.code,
        message: params?.message,
      };
    }),
    sleep(sessionRequestHoldMs).then(() => ({
      outcome: "session_delete_timeout",
      topic,
    })),
  ]);
  await writeResult(response);
}

function onceSignClientEvent(
  eventName: "session_update" | "session_extend" | "session_event" | "session_delete",
  topic: string,
): Promise<{
  id: number | bigint;
  topic: string;
  params?: unknown;
}> {
  return new Promise((resolve) => {
    const listener = (event: {
      id: number | bigint;
      topic: string;
      params?: unknown;
    }) => {
      if (event.topic !== topic) {
        return;
      }
      signClient.off(eventName, listener);
      resolve(event);
    };
    signClient.on(eventName, listener);
  });
}

function stringifyId(id: number | bigint): string {
  return typeof id === "bigint" ? id.toString() : String(id);
}

function stringifyForLog(value: unknown): string {
  return JSON.stringify(valueForLog(value));
}

function sessionRequestResultForLog(result: unknown): string {
  if (logDecryptedPayloads) {
    return stringifyForLog(result);
  }

  return JSON.stringify(redactedSummary(result));
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

function sessionRequestParams(namespaces?: unknown): unknown {
  const paramsJson = process.env.WC_JS_SESSION_REQUEST_PARAMS_JSON;
  if (paramsJson) {
    return replaceSessionRequestPlaceholders(
      JSON.parse(paramsJson) as unknown,
      approvedBip122Address(namespaces, process.env.WC_JS_SESSION_REQUEST_CHAIN_ID),
    );
  }

  const address =
    process.env.WC_JS_SESSION_REQUEST_ACCOUNT_ADDRESS ??
    "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb";
  return ["0x68656c6c6f", address];
}

function replaceSessionRequestPlaceholders(value: unknown, bip122Address?: string): unknown {
  if (typeof value === "string") {
    return value.replaceAll("__WC_APPROVED_BIP122_ADDRESS__", bip122Address ?? "");
  }

  if (Array.isArray(value)) {
    return value.map((item) => replaceSessionRequestPlaceholders(item, bip122Address));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([entryKey, entryValue]) => [
        entryKey,
        replaceSessionRequestPlaceholders(entryValue, bip122Address),
      ]),
    );
  }

  return value;
}

function approvedBip122Address(namespaces: unknown, preferredChainId?: string): string | undefined {
  const bip122 = (namespaces as { bip122?: { accounts?: unknown } } | undefined)?.bip122;
  const accounts = bip122?.accounts;
  if (!Array.isArray(accounts)) {
    return undefined;
  }

  const bip122Accounts = accounts.filter(
    (entry): entry is string => typeof entry === "string" && entry.startsWith("bip122:"),
  );
  const account =
    preferredChainId === undefined
      ? bip122Accounts[0]
      : bip122Accounts.find((entry) => entry.startsWith(`${preferredChainId}:`)) ?? bip122Accounts[0];
  return account?.split(":").at(-1);
}

function sessionEventData(): unknown {
  const dataJson = process.env.WC_JS_SESSION_EVENT_DATA_JSON;
  if (dataJson) {
    return JSON.parse(dataJson) as unknown;
  }

  return ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"];
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

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
