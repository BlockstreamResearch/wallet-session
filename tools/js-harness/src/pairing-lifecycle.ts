import { SignClient } from "@walletconnect/sign-client";

const projectId = process.env.REOWN_PROJECT_ID ?? process.env.WALLETCONNECT_PROJECT_ID;

if (!projectId) {
  console.error("set REOWN_PROJECT_ID or WALLETCONNECT_PROJECT_ID");
  process.exit(1);
}

const relayUrl = process.env.REOWN_RELAY_URL ?? "wss://relay.walletconnect.com";
const holdMs = Number.parseInt(process.env.WC_JS_HARNESS_HOLD_MS ?? "30000", 10);
const uriFile = process.env.WC_JS_URI_FILE;
const resultFile = process.env.WC_JS_RESULT_FILE;
const action = process.env.WC_JS_PAIRING_ACTION ?? "ping";

if (!uriFile) {
  console.error("set WC_JS_URI_FILE");
  process.exit(1);
}

const signClient = await SignClient.init({
  projectId,
  relayUrl,
  metadata: {
    name: "walletconnect-client-poc JS pairing harness",
    description: "Live WalletConnect pairing lifecycle probe for Rust protocol tests",
    url: "https://github.com/BlockstreamResearch/walletconnect-client-poc",
    icons: ["https://walletconnect.com/walletconnect-logo.png"],
  },
});

const { topic, uri } = await signClient.core.pairing.create();

await Bun.write(uriFile, `${uri}\n`);
console.error(
  `js-harness pairing_uri_ready=true action=${action} topic=${topic} hold_ms=${holdMs} uri=${redactPairingUri(
    uri,
  )}`,
);

let exitCode = 0;

try {
  switch (action) {
    case "ping":
      await startPairingPing(topic);
      break;
    case "delete":
      await startPairingDelete(topic);
      break;
    default:
      throw new Error(`unknown WC_JS_PAIRING_ACTION=${action}`);
  }
} catch (error) {
  exitCode = 1;
  const message = errorMessage(error);
  console.error(`js-harness pairing_lifecycle_error=${message}`);
  await writeResult({
    outcome: "pairing_lifecycle_error",
    topic,
    message,
  });
} finally {
  await signClient.core.relayer.transportClose();
}

process.exit(exitCode);

function redactPairingUri(uri: string): string {
  return uri.replace(/([?&]symKey=)[^&]+/, "$1<redacted>");
}

async function writeResult(result: Record<string, unknown>): Promise<void> {
  if (!resultFile) {
    return;
  }

  await Bun.write(resultFile, `${JSON.stringify(result)}\n`);
}

async function startPairingPing(topic: string): Promise<void> {
  const request = signClient.core.pairing.ping({ topic });
  console.error(`js-harness pairing_ping_started=true topic=${topic} hold_ms=${holdMs}`);

  const response = await Promise.race([
    request.then(
      () => {
        console.error("js-harness pairing_ping_response=true");
        return {
          outcome: "pairing_ping_response",
          topic,
        };
      },
      (error) => {
        const message = errorMessage(error);
        console.error(`js-harness pairing_ping_error=${message}`);
        return {
          outcome: "pairing_ping_error",
          topic,
          message,
        };
      },
    ),
    sleep(holdMs).then(() => ({
      outcome: "pairing_ping_timeout",
      topic,
    })),
  ]);

  await writeResult(response);
}

async function startPairingDelete(topic: string): Promise<void> {
  const request = signClient.core.pairing.disconnect({ topic });
  console.error(`js-harness pairing_delete_started=true topic=${topic}`);

  const response = await request.then(
    () => {
      console.error("js-harness pairing_delete_sent=true");
      return {
        outcome: "pairing_delete_sent",
        topic,
      };
    },
    (error) => {
      const message = errorMessage(error);
      console.error(`js-harness pairing_delete_error=${message}`);
      return {
        outcome: "pairing_delete_error",
        topic,
        message,
      };
    },
  );

  await writeResult(response);
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
