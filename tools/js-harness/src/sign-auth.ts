import { buildAuthObject, formatMessage, validateSignedCacao } from "@walletconnect/utils";
import { Address, Hex, PersonalMessage, Secp256k1, Signature } from "ox";

// `@walletconnect/utils` mirrors the maintained SDK's CACAO formatting and
// validation helpers used by one-click auth.
// https://docs.walletconnect.network/wallet-sdk/web/one-click-auth#authentication-objectspayloads
//
// `ox` signs the live harness message as the external wallet/caller. The Rust
// core still receives caller-provided CACAOs and does not own signing keys.
// https://oxlib.sh/api/Secp256k1/sign

const authPayloadJson = process.env.WC_JS_AUTH_PAYLOAD_JSON;
if (!authPayloadJson) {
  console.error("set WC_JS_AUTH_PAYLOAD_JSON");
  process.exit(1);
}

const privateKey =
  process.env.WC_JS_AUTH_PRIVATE_KEY ??
  "0x59c6995e998f97a5a0044966f09453817dc7d2879b11531b17903b4bdef77a31";
const typedPrivateKey = privateKey as `0x${string}`;
const publicKey = Secp256k1.getPublicKey({ privateKey: typedPrivateKey });
const address = Address.fromPublicKey(publicKey);
const authPayload = JSON.parse(authPayloadJson) as Parameters<typeof buildAuthObject>[0] & {
  chains?: string[];
  [key: string]: unknown;
};
const chain = process.env.WC_JS_AUTH_SIGN_CHAIN ?? authPayload.chains?.[0];

if (!chain) {
  console.error("set WC_JS_AUTH_SIGN_CHAIN or provide authPayload.chains[0]");
  process.exit(1);
}

const iss = `${chain}:${address}`;
const message = formatMessage(authPayload, iss);
const payload = PersonalMessage.getSignPayload(Hex.fromString(message));
const signature = Signature.toHex(
  Secp256k1.sign({
    payload,
    privateKey: typedPrivateKey,
    extraEntropy: false,
  }),
);
const cacao = buildAuthObject(authPayload, { t: "eip191", s: signature }, iss);
const valid = await validateSignedCacao({ cacao });

if (!valid) {
  console.error("signed CACAO did not validate locally");
  process.exit(1);
}

console.log(
  JSON.stringify({
    address,
    iss: `did:pkh:${iss}`,
    cacao,
  }),
);
