const te = new TextEncoder();

function bytes(...items) {
  const arrays = items.flat().map(item => item instanceof Uint8Array ? item : new Uint8Array(item));
  const output = new Uint8Array(arrays.reduce((total, item) => total + item.length, 0));
  let offset = 0;
  for (const item of arrays) { output.set(item, offset); offset += item.length; }
  return output;
}

function lengthBytes(length) {
  if (length < 128) return Uint8Array.of(length);
  const result = [];
  while (length) { result.unshift(length & 0xff); length >>>= 8; }
  return Uint8Array.of(0x80 | result.length, ...result);
}

function der(tag, content = new Uint8Array()) { return bytes(Uint8Array.of(tag), lengthBytes(content.length), content); }
const sequence = (...items) => der(0x30, bytes(...items));
const integer = value => der(0x02, value === 0 ? Uint8Array.of(0) : Uint8Array.of(value));
const bool = value => der(0x01, Uint8Array.of(value ? 0xff : 0));
const nullValue = () => der(0x05);
const octetString = value => der(0x04, value);
const bitString = (value, unused = 0) => der(0x03, bytes(Uint8Array.of(unused), value));

function oid(text) {
  const parts = text.split(".").map(Number);
  const result = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const encoded = [part & 0x7f];
    let value = part >>> 7;
    while (value) { encoded.unshift(0x80 | (value & 0x7f)); value >>>= 7; }
    result.push(...encoded);
  }
  return der(0x06, Uint8Array.from(result));
}

const rsaAlgorithm = () => sequence(oid("1.2.840.113549.1.1.1"), nullValue());
const signatureAlgorithm = () => sequence(oid("1.2.840.113549.1.1.11"), nullValue());
const extension = (id, critical, value) => sequence(oid(id), ...(critical ? [bool(true)] : []), octetString(value));

function utcTime(date) {
  const two = value => String(value).padStart(2, "0");
  const year = two(date.getUTCFullYear() % 100);
  return der(0x17, te.encode(`${year}${two(date.getUTCMonth() + 1)}${two(date.getUTCDate())}${two(date.getUTCHours())}${two(date.getUTCMinutes())}${two(date.getUTCSeconds())}Z`));
}

function pem(label, derBytes) {
  let binary = "";
  for (let i = 0; i < derBytes.length; i += 0x8000) binary += String.fromCharCode(...derBytes.subarray(i, i + 0x8000));
  const encoded = btoa(binary).match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${encoded}\n-----END ${label}-----\n`;
}

function parsePem(value) {
  const match = value.match(/-----BEGIN ([^-]+)-----([\s\S]+?)-----END \1-----/);
  if (!match) throw new Error("Invalid device public key PEM.");
  const binary = atob(match[2].replace(/\s/g, ""));
  return { label: match[1], der: Uint8Array.from(binary, character => character.charCodeAt(0)) };
}

function subjectPublicKeyInfo(publicKeyPem) {
  const parsed = parsePem(publicKeyPem);
  if (parsed.label === "PUBLIC KEY") return parsed.der;
  if (parsed.label === "RSA PUBLIC KEY") return sequence(rsaAlgorithm(), bitString(parsed.der));
  throw new Error(`Unsupported device key type: ${parsed.label}`);
}

async function certificate(subjectSpki, signerKey, kind) {
  const now = new Date(Date.now() - 60_000);
  const later = new Date(now); later.setUTCFullYear(later.getUTCFullYear() + 10);
  const extensions = [];
  if (kind === "root") {
    extensions.push(extension("2.5.29.19", true, sequence(bool(true))));
  } else {
    extensions.push(extension("2.5.29.19", true, sequence()));
    extensions.push(extension("2.5.29.15", true, bitString(Uint8Array.of(0xa0), 5)));
  }
  const tbs = sequence(
    der(0xa0, integer(2)), integer(0), signatureAlgorithm(), sequence(),
    sequence(utcTime(now), utcTime(later)), sequence(), subjectSpki,
    der(0xa3, sequence(...extensions))
  );
  const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signerKey, tbs));
  return sequence(tbs, signatureAlgorithm(), bitString(signature));
}

async function exportPrivatePem(key) {
  return pem("PRIVATE KEY", new Uint8Array(await crypto.subtle.exportKey("pkcs8", key)));
}

export async function generatePairingIdentity(devicePublicKeyBytes) {
  const algorithm = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256" };
  const [root, host] = await Promise.all([
    crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]),
    crypto.subtle.generateKey(algorithm, true, ["sign", "verify"])
  ]);
  const rootSpki = new Uint8Array(await crypto.subtle.exportKey("spki", root.publicKey));
  const hostSpki = new Uint8Array(await crypto.subtle.exportKey("spki", host.publicKey));
  const devicePem = new TextDecoder().decode(devicePublicKeyBytes);
  const [rootCert, hostCert, deviceCert] = await Promise.all([
    certificate(rootSpki, root.privateKey, "root"),
    certificate(hostSpki, root.privateKey, "host"),
    certificate(subjectPublicKeyInfo(devicePem), root.privateKey, "device")
  ]);
  return {
    rootCertificate: te.encode(pem("CERTIFICATE", rootCert)),
    hostCertificate: te.encode(pem("CERTIFICATE", hostCert)),
    deviceCertificate: te.encode(pem("CERTIFICATE", deviceCert)),
    rootPrivateKey: await exportPrivatePem(root.privateKey),
    hostPrivateKey: await exportPrivatePem(host.privateKey)
  };
}
