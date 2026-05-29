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
  await Bun.write(resultFile, JSON.stringify(result, null, 2));
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function stringifyForLog(value: unknown): string {
  return JSON.stringify(value, (_key, item) => (typeof item === "bigint" ? item.toString() : item));
}
