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
    if (sendSessionRequest) {
      await startSessionRequest(session.topic);
    } else {
      await writeResult({
        outcome: "approved",
        topic: session.topic,
      });
    }
  } else {
    console.error("js-harness proposal_timeout=true");
    await writeResult({
      outcome: "timeout",
    });
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
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

async function writeResult(result: Record<string, string>): Promise<void> {
  if (!resultFile) {
    return;
  }

  await Bun.write(resultFile, `${JSON.stringify(result)}\n`);
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
      const message = error instanceof Error ? error.message : String(error);
      console.error(`js-harness session_request_error=${message}`);
      await writeResult({
        outcome: "session_request_error",
        topic,
        chainId,
        method,
        message,
      });
    });

  console.error(
    `js-harness session_request_started=true topic=${topic} chain_id=${chainId} method=${method} hold_ms=${sessionRequestHoldMs}`,
  );
  await writeResult({
    outcome: "session_request_started",
    topic,
    chainId,
    method,
  });
  await sleep(sessionRequestHoldMs);
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

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
