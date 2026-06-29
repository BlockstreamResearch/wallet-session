import { existsSync } from "node:fs";
import { chromium, type Browser, type Page } from "playwright-core";

type LabAction = "inspect" | "signMessage" | "sendTransfer" | "signPsbt";

const baseUrl = process.env.WC_LAB_BASE_URL ?? "https://lab.reown.com/";
const timeoutMs = readIntEnv("WC_LAB_TIMEOUT_MS", 20_000);
const holdMs = readIntEnv("WC_LAB_HOLD_MS", 120_000);
const action = readAction(process.env.WC_LAB_ACTION ?? "inspect");
const psbtAmount = process.env.WC_LAB_PSBT_AMOUNT;
const psbtRecipient = process.env.WC_LAB_PSBT_RECIPIENT;
const psbtBroadcast = process.env.WC_LAB_PSBT_BROADCAST;
const sendTransferRecipient = process.env.WC_LAB_SEND_TRANSFER_RECIPIENT;
const sendTransferAmount = process.env.WC_LAB_SEND_TRANSFER_AMOUNT;
const signMessageProtocol = process.env.WC_LAB_SIGN_MESSAGE_PROTOCOL;
const bitcoinNetwork = process.env.WC_LAB_BITCOIN_NETWORK;

let browser: Browser | undefined;

try {
  browser = await chromium.launch({
    executablePath: findBrowserExecutable(),
    headless: process.env.WC_LAB_HEADED !== "1",
  });
  const page = await browser.newPage();
  page.on("console", (message) => {
    if (message.type() === "error" || message.type() === "warning") {
      const text = message.text();
      if (!text.includes("Executing inline script violates")) {
        console.error(`[browser.${message.type()}] ${text}`);
      }
    }
  });

  await openWalletConnectModal(page);
  const uri = await readQrUri(page);
  console.log(`WC_LAB_PAIRING_URI=${uri}`);

  await waitForBitcoinConnected(page);
  console.log(`WC_LAB_CONNECTED=${JSON.stringify(await labSnapshot(page))}`);

  if (action !== "inspect") {
    await runAction(page, action);
  }

  await page.waitForTimeout(holdMs);
} finally {
  await browser?.close();
}

async function openWalletConnectModal(page: Page): Promise<void> {
  await page.goto(new URL("/appkit?name=bitcoin", normalizedBaseUrl(baseUrl)).toString(), {
    waitUntil: "domcontentloaded",
    timeout: timeoutMs,
  });

  if (bitcoinNetwork) {
    await selectBitcoinNetwork(page, bitcoinNetwork);
  }

  await page.getByTestId("connect-button").first().click({ timeout: timeoutMs });
  await page.getByTestId("wallet-selector-walletconnect").click({ timeout: timeoutMs });
}

async function selectBitcoinNetwork(page: Page, network: string): Promise<void> {
  const target = bitcoinNetworkTarget(network);
  await page.getByTestId("wui-network-button").click({ timeout: timeoutMs });
  await page.getByTestId(`w3m-network-switch-${target.label}`).click({ timeout: timeoutMs });

  const expectedNetworkId = `bip122:${target.genesisHash}`;
  await waitForVisibleText(page, expectedNetworkId);
  await closeAppKitModal(page);
  console.log(`WC_LAB_BITCOIN_NETWORK_SELECTED=${target.label}`);
  console.log(`WC_LAB_BITCOIN_CAIP_NETWORK_ID=${expectedNetworkId}`);
}

async function closeAppKitModal(page: Page): Promise<void> {
  await page.keyboard.press("Escape");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const className = await page.locator("w3m-modal").getAttribute("class").catch(() => "");
    if (!className?.includes("open")) {
      return;
    }
    await page.waitForTimeout(250);
  }
  throw new Error("AppKit modal did not close");
}

async function waitForVisibleText(page: Page, expected: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const text = await page.locator("body").innerText({ timeout: 1_000 }).catch(() => "");
    if (text.includes(expected)) {
      return;
    }
    await page.waitForTimeout(250);
  }
  throw new Error(`visible text did not include ${expected}`);
}

async function readQrUri(page: Page): Promise<string> {
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

async function waitForBitcoinConnected(page: Page): Promise<void> {
  const deadline = Date.now() + holdMs;
  let lastLogged = "";
  while (Date.now() < deadline) {
    const text = await page.locator("body").innerText({ timeout: 1_000 }).catch(() => "");
    if (
      text.includes("Wallet Info") ||
      text.includes("Wallet Info Type") ||
      text.includes("WALLET_CONNECT") ||
      text.includes("signPsbt") ||
      text.includes("Sign PSBT") ||
      text.includes("Sign Message") ||
      text.includes("Send Transfer")
    ) {
      return;
    }
    const lines = uniqueVisibleLines(text).slice(0, 40);
    const compact = JSON.stringify(lines);
    if (compact !== lastLogged) {
      console.log(`WC_LAB_WAITING=${compact}`);
      lastLogged = compact;
    }
    await page.waitForTimeout(500);
  }
  throw new Error("Lab did not reach the Bitcoin connected state");
}

async function runAction(page: Page, currentAction: LabAction): Promise<void> {
  if (currentAction === "signMessage" && signMessageProtocol) {
    await selectSignMessageProtocol(page, signMessageProtocol);
  }

  if (currentAction === "signPsbt" && psbtAmount !== undefined) {
    await fillInput(page, 'input[type="number"]', 0, psbtAmount);
    console.log(`WC_LAB_PSBT_AMOUNT_SET=${psbtAmount}`);
  }
  if (currentAction === "signPsbt" && psbtRecipient !== undefined) {
    await fillInput(page, 'input[type="text"]', 1, psbtRecipient);
    console.log(`WC_LAB_PSBT_RECIPIENT_SET=${psbtRecipient}`);
  }
  if (currentAction === "signPsbt" && psbtBroadcast !== undefined) {
    await setCheckbox(page, 0, readBooleanEnv("WC_LAB_PSBT_BROADCAST", psbtBroadcast));
    console.log(`WC_LAB_PSBT_BROADCAST_SET=${psbtBroadcast}`);
  }
  if (currentAction === "sendTransfer" && sendTransferRecipient !== undefined) {
    await fillInput(page, 'input[type="text"]', 2, sendTransferRecipient);
    console.log(`WC_LAB_SEND_TRANSFER_RECIPIENT_SET=${sendTransferRecipient}`);
  }
  if (currentAction === "sendTransfer" && sendTransferAmount !== undefined) {
    await fillInput(page, 'input[type="number"]', 1, sendTransferAmount);
    console.log(`WC_LAB_SEND_TRANSFER_AMOUNT_SET=${sendTransferAmount}`);
  }

  const buttonTestId =
    currentAction === "signMessage"
      ? "sign-message-button"
      : currentAction === "sendTransfer"
        ? "send-transfer-button"
        : "sign-psbt-button";
  await page.getByTestId(buttonTestId).click({ timeout: timeoutMs });
  console.log(`WC_LAB_ACTION_CLICKED=${currentAction}`);

  const deadline = Date.now() + holdMs;
  let lastState = "";
  while (Date.now() < deadline) {
    const snapshot = await labSnapshot(page);
    const state = JSON.stringify(snapshot);
    if (state !== lastState) {
      console.log(`WC_LAB_STATE=${state}`);
      lastState = state;
    }
    if (
      snapshot.visibleText.some(
        (line) =>
          line.includes("Signing Succeeded") ||
          line.includes("PSBT Signature") ||
          line.includes("Transaction Sent") ||
          line.startsWith("Error ") ||
          line === "Error",
      )
    ) {
      return;
    }
    await page.waitForTimeout(1_000);
  }
}

async function fillInput(page: Page, selector: string, index: number, value: string): Promise<void> {
  const input = page.locator(selector).nth(index);
  await input.waitFor({ state: "visible", timeout: timeoutMs });
  await input.fill(value, { timeout: timeoutMs });
}

async function setCheckbox(page: Page, index: number, checked: boolean): Promise<void> {
  const checkbox = page.locator('input[type="checkbox"]').nth(index);
  await checkbox.waitFor({ state: "attached", timeout: timeoutMs });
  if (checked) {
    await checkbox.check({ timeout: timeoutMs });
  } else {
    await checkbox.uncheck({ timeout: timeoutMs });
  }
}

async function selectSignMessageProtocol(page: Page, protocol: string): Promise<void> {
  const label = protocol === "bip322" ? "BIP-322" : protocol === "ecdsa" ? "ECDSA" : protocol;
  await page.getByRole("combobox").first().selectOption({ label }, { timeout: timeoutMs });
  console.log(`WC_LAB_SIGN_MESSAGE_PROTOCOL_SELECTED=${label}`);
}

async function labSnapshot(page: Page): Promise<{ inputs: string[]; visibleText: string[] }> {
  const text = await page.locator("body").innerText({ timeout: timeoutMs }).catch(() => "");
  const visibleText = uniqueVisibleLines(text).slice(0, 80);
  const inputCount = await page.locator("input").count();
  const inputs: string[] = [];
  for (let index = 0; index < inputCount; index += 1) {
    const input = page.locator("input").nth(index);
    const type = await input.getAttribute("type").catch(() => null);
    const value = await input.inputValue().catch(() => "");
    inputs.push(`${type ?? "text"}:${value}`);
  }
  return { inputs, visibleText };
}

function uniqueVisibleLines(text: string): string[] {
  return text
    .split("\n")
    .map((line: string) => line.trim())
    .filter(Boolean)
    .filter((line: string, index: number, lines: string[]) => lines.indexOf(line) === index);
}

function readAction(value: string): LabAction {
  if (value === "inspect" || value === "signMessage" || value === "sendTransfer" || value === "signPsbt") {
    return value;
  }
  throw new Error(`unsupported WC_LAB_ACTION=${value}`);
}

function bitcoinNetworkTarget(value: string): { genesisHash: string; label: string } {
  if (value === "mainnet" || value === "bitcoin") {
    return { genesisHash: "000000000019d6689c085ae165831e93", label: "Bitcoin" };
  }
  if (value === "testnet" || value === "bitcoin-testnet") {
    return { genesisHash: "000000000933ea01ad0ee984209779ba", label: "Bitcoin Testnet" };
  }
  if (value === "signet" || value === "bitcoin-signet") {
    return { genesisHash: "00000008819873e925422c1ff0f99f7c", label: "Bitcoin Signet" };
  }
  throw new Error(`unsupported WC_LAB_BITCOIN_NETWORK=${value}`);
}

function readIntEnv(name: string, fallback: number): number {
  const value = process.env[name];
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function readBooleanEnv(name: string, value: string): boolean {
  if (value === "1" || value === "true" || value === "yes" || value === "on") {
    return true;
  }
  if (value === "0" || value === "false" || value === "no" || value === "off") {
    return false;
  }
  throw new Error(`${name} must be a boolean-like value`);
}

function normalizedBaseUrl(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
}

function findBrowserExecutable(): string {
  const explicit = process.env.WC_LAB_BROWSER;
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
