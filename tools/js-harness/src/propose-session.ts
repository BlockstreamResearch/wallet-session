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
const sendSessionRequest = process.env.WC_JS_SEND_SESSION_REQUEST === "1";
const afterApprovalAction =
  process.env.WC_JS_AFTER_APPROVAL_ACTION ?? (sendSessionRequest ? "session_request" : "approved");
const waitForSessionRequestResponse =
  process.env.WC_JS_SESSION_REQUEST_WAIT_FOR_RESPONSE === "1";

if (!uriFile && !printUri) {
  console.error("set WC_JS_URI_FILE or set WC_JS_PRINT_URI=1 to print the full pairing URI");
  process.exit(1);
}

const signClient = await SignClient.init({
  projectId,
  relayUrl,
  metadata: {
    name: "walletconnect-client-poc JS harness",
    description: "Live WalletConnect proposal generator for Rust protocol probes",
    url: "https://github.com/BlockstreamResearch/walletconnect-client-poc",
    icons: ["https://walletconnect.com/walletconnect-logo.png"],
  },
});

const { uri, approval } = await signClient.connect({
  requiredNamespaces: {
    eip155: {
      chains: ["eip155:1"],
      methods: ["personal_sign", "eth_signTypedData_v4"],
      events: ["accountsChanged", "chainChanged"],
    },
  },
});

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
    switch (afterApprovalAction) {
      case "approved":
        await writeResult({
          outcome: "approved",
          topic: session.topic,
        });
        break;
      case "session_request":
        await startSessionRequest(session.topic);
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
      case "session_extend":
        await startSessionExtend(session.topic);
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

async function writeResult(result: Record<string, unknown>): Promise<void> {
  if (!resultFile) {
    return;
  }

  await Bun.write(resultFile, `${JSON.stringify(result)}\n`);
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

async function startSessionRequest(topic: string): Promise<void> {
  const chainId = process.env.WC_JS_SESSION_REQUEST_CHAIN_ID ?? "eip155:1";
  const method = process.env.WC_JS_SESSION_REQUEST_METHOD ?? "personal_sign";
  const expiry = Number.parseInt(process.env.WC_JS_SESSION_REQUEST_EXPIRY ?? "300", 10);
  const params = sessionRequestParams();

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
          console.error(`js-harness session_request_response=${JSON.stringify(result)}`);
          return {
            outcome: "session_request_response",
            topic,
            chainId,
            method,
            result: JSON.stringify(result),
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
      console.error(`js-harness session_request_response=${JSON.stringify(result)}`);
      await writeResult({
        outcome: "session_request_response",
        topic,
        chainId,
        method,
        result: JSON.stringify(result),
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
  return JSON.stringify(value, (_key, item) =>
    typeof item === "bigint" ? item.toString() : item,
  );
}

function sessionRequestParams(): unknown {
  const paramsJson = process.env.WC_JS_SESSION_REQUEST_PARAMS_JSON;
  if (paramsJson) {
    return JSON.parse(paramsJson) as unknown;
  }

  const address =
    process.env.WC_JS_SESSION_REQUEST_ACCOUNT_ADDRESS ??
    "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb";
  return ["0x68656c6c6f", address];
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  if (typeof error === "object" && error !== null) {
    return JSON.stringify(error);
  }

  return String(error);
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
