import { SignClient } from "@walletconnect/sign-client";

const projectId = process.env.REOWN_PROJECT_ID ?? process.env.WALLETCONNECT_PROJECT_ID;

if (!projectId) {
  console.error("set REOWN_PROJECT_ID or WALLETCONNECT_PROJECT_ID");
  process.exit(1);
}

const relayUrl = process.env.REOWN_RELAY_URL ?? "wss://relay.walletconnect.com";
const resultFile = process.env.WC_JS_RESULT_FILE;
const timeoutMs = Number.parseInt(process.env.WC_JS_HARNESS_HOLD_MS ?? "45000", 10);
const storageSuffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;

const dapp = await SignClient.init({
  projectId,
  relayUrl,
  customStoragePrefix: `wc-live-verify-dapp-${storageSuffix}`,
  metadata: {
    name: "walletconnect-client-poc verify dapp",
    description: "Live Verify context dapp",
    url: process.env.WC_JS_VERIFY_DAPP_URL ?? "https://example.com",
    icons: ["https://walletconnect.com/walletconnect-logo.png"],
  },
});

const wallet = await SignClient.init({
  projectId,
  relayUrl,
  customStoragePrefix: `wc-live-verify-wallet-${storageSuffix}`,
  metadata: {
    name: "walletconnect-client-poc verify wallet",
    description: "Live Verify context wallet",
    url: "https://example.com/wallet",
    icons: ["https://walletconnect.com/walletconnect-logo.png"],
  },
});

try {
  const proposalEvent = new Promise<Record<string, unknown>>((resolve) => {
    wallet.once("session_proposal", (event) => {
      resolve({
        id: event.id,
        verifyContext: event.verifyContext,
        paramsKeys: Object.keys(event.params ?? {}).sort(),
        dappUrl: event.params?.proposer?.metadata?.url,
      });
    });
  });

  const { uri } = await dapp.connect({
    requiredNamespaces: {
      eip155: {
        chains: ["eip155:1"],
        methods: ["personal_sign"],
        events: ["accountsChanged"],
      },
    },
  });

  if (!uri) {
    throw new Error("sign-client did not return a pairing URI");
  }

  await wallet.pair({ uri });

  const result = await Promise.race([
    proposalEvent,
    sleep(timeoutMs).then(() => {
      throw new Error("session_proposal timeout");
    }),
  ]);

  const json = JSON.stringify(result, null, 2);
  console.log(json);

  if (resultFile) {
    await Bun.write(resultFile, `${json}\n`);
  }
} finally {
  await Promise.allSettled([
    dapp.core.relayer.transportClose(),
    wallet.core.relayer.transportClose(),
  ]);
}

process.exit(0);

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
