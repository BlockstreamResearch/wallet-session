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
    await writeResult({
      outcome: "approved",
      topic: session.topic,
    });
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
