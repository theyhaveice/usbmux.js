import { encodePlist, decodePlist } from "./plist.js";
import { generatePairingIdentity } from "./x509.js";

const APPLE_VENDOR_ID = 0x05ac;
const LOCKDOWN_PORT = 62078;

function cleanUsbString(value) {
  return value?.replaceAll("\0", "").trim() || "iphone";
}

function concat(...arrays) {
  const output = new Uint8Array(arrays.reduce((total, value) => total + value.length, 0));
  let offset = 0;
  for (const value of arrays) { output.set(value, offset); offset += value.length; }
  return output;
}

class AppleMux {
  constructor(device, inEndpoint, outEndpoint) {
    this.device = device;
    this.inEndpoint = inEndpoint;
    this.outEndpoint = outEndpoint;
    this.version = 0;
    this.rawTx = 0;
    this.rawRx = 0xffff;
    this.pending = new Uint8Array();
  }

  async usbWrite(bytes) {
    const result = await this.device.transferOut(this.outEndpoint, bytes);
    if (result.status !== "ok") throw new Error(`USB write failed: ${result.status}`);
  }

  async readPacket() {
    while (true) {
      if (this.pending.length >= 8) {
        const expected = new DataView(this.pending.buffer, this.pending.byteOffset, this.pending.byteLength).getUint32(4);
        if (expected < 8 || expected > 1024 * 1024) throw new Error(`Invalid raw mux packet length ${expected}.`);
        if (this.pending.length >= expected) {
          const bytes = this.pending.slice(0, expected);
          this.pending = this.pending.slice(expected);
          const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
          if (this.version >= 2 && bytes.length >= 16) this.rawRx = view.getUint16(14);
          return { bytes, view, protocol: view.getUint32(0) };
        }
      }
      const result = await this.device.transferIn(this.inEndpoint, 16384);
      if (result.status !== "ok" || !result.data) throw new Error(`USB read failed: ${result.status}`);
      const part = new Uint8Array(result.data.buffer, result.data.byteOffset, result.data.byteLength);
      if (part.length) this.pending = concat(this.pending, part);
    }
  }

  async send(protocol, header = new Uint8Array(), payload = new Uint8Array()) {
    const muxHeaderLength = this.version >= 2 ? 16 : 8;
    const packet = new Uint8Array(muxHeaderLength + header.length + payload.length);
    const view = new DataView(packet.buffer);
    view.setUint32(0, protocol);
    view.setUint32(4, packet.length);
    if (this.version >= 2) {
      view.setUint32(8, 0xfeedface);
      if (protocol === 2) { this.rawTx = 0; this.rawRx = 0xffff; }
      view.setUint16(12, this.rawTx++);
      view.setUint16(14, this.rawRx);
    }
    packet.set(header, muxHeaderLength);
    packet.set(payload, muxHeaderLength + header.length);
    await this.usbWrite(packet);
  }

  async initialise() {
    const versionHeader = new Uint8Array(12);
    const view = new DataView(versionHeader.buffer);
    view.setUint32(0, 2); view.setUint32(4, 0); view.setUint32(8, 0);
    await this.send(0, versionHeader);
    let reply;
    do { reply = await this.readPacket(); } while (reply.protocol !== 0);
    if (reply.bytes.length < 20) throw new Error("Short iPhone mux version response.");
    this.version = reply.view.getUint32(8);
    const minor = reply.view.getUint32(12);
    if (this.version !== 1 && this.version !== 2) throw new Error(`Unsupported iPhone mux ${this.version}.${minor}.`);
    if (this.version >= 2) await this.send(2, new Uint8Array(), Uint8Array.of(7));
  }

  tcpPacket(connection, flags, payload = new Uint8Array()) {
    const header = new Uint8Array(20);
    const view = new DataView(header.buffer);
    view.setUint16(0, connection.sourcePort);
    view.setUint16(2, connection.destinationPort);
    view.setUint32(4, connection.txSequence);
    view.setUint32(8, connection.txAcknowledgement);
    header[12] = 0x50;
    header[13] = flags;
    view.setUint16(14, 512);
    return { header, payload };
  }

  async sendTcp(connection, flags, payload = new Uint8Array()) {
    const packet = this.tcpPacket(connection, flags, payload);
    await this.send(6, packet.header, packet.payload);
    connection.txSequence += payload.length;
  }

  async nextTcp(connection) {
    while (true) {
      const packet = await this.readPacket();
      if (packet.protocol !== 6 || packet.bytes.length < 36) continue;
      const offset = this.version >= 2 ? 16 : 8;
      const sourcePort = packet.view.getUint16(offset);
      const destinationPort = packet.view.getUint16(offset + 2);
      if (sourcePort !== connection.destinationPort || destinationPort !== connection.sourcePort) continue;
      return {
        flags: packet.bytes[offset + 13],
        sequence: packet.view.getUint32(offset + 4),
        acknowledgement: packet.view.getUint32(offset + 8),
        payload: packet.bytes.slice(offset + 20)
      };
    }
  }

  async connect(destinationPort) {
    const connection = {
      sourcePort: 49152 + crypto.getRandomValues(new Uint16Array(1))[0] % 12000,
      destinationPort, txSequence: 0, txAcknowledgement: 0, receiveBuffer: new Uint8Array()
    };
    await this.sendTcp(connection, 0x02);
    const reply = await this.nextTcp(connection);
    if (reply.flags !== 0x12) throw new Error(`Port ${destinationPort} refused the mux connection (TCP flags 0x${reply.flags.toString(16)}).`);
    connection.txSequence = 1;
    connection.txAcknowledgement = reply.acknowledgement + 1;
    await this.sendTcp(connection, 0x10);
    return connection;
  }

  async write(connection, payload) {
    // Apple mux TCP requires TH_ACK exactly, including for packets containing data.
    const maximum = 16384 - (this.version >= 2 ? 36 : 28);
    for (let offset = 0; offset < payload.length; offset += maximum) {
      await this.sendTcp(connection, 0x10, payload.slice(offset, offset + maximum));
    }
  }

  async read(connection, count) {
    while (connection.receiveBuffer.length < count) {
      const packet = await this.nextTcp(connection);
      if (packet.flags & 0x04) throw new Error("The iPhone reset the lockdownd connection.");
      if (packet.flags !== 0x10) throw new Error(`Unexpected lockdownd TCP flags 0x${packet.flags.toString(16)}.`);
      if (packet.payload.length) {
        connection.receiveBuffer = concat(connection.receiveBuffer, packet.payload);
        connection.txAcknowledgement += packet.payload.length;
        await this.sendTcp(connection, 0x10);
      }
    }
    const result = connection.receiveBuffer.slice(0, count);
    connection.receiveBuffer = connection.receiveBuffer.slice(count);
    return result;
  }

  async lockdownRequest(connection, request) {
    const body = encodePlist(request);
    const frame = new Uint8Array(4 + body.length);
    new DataView(frame.buffer).setUint32(0, body.length);
    frame.set(body, 4);
    await this.write(connection, frame);
    const lengthBytes = await this.read(connection, 4);
    const length = new DataView(lengthBytes.buffer, lengthBytes.byteOffset, 4).getUint32(0);
    if (length > 4 * 1024 * 1024) throw new Error(`Unreasonable lockdownd response length ${length}.`);
    return decodePlist(await this.read(connection, length));
  }
}

function identityKey(label, serial) {
  return `usbmux-pairing:${label}:${serial || "iphone"}`;
}

function saveIdentity(storage, label, serial, identity, record) {
  if (!storage) return;
  storage.setItem(identityKey(label, serial), JSON.stringify({
    serialNumber: serial,
    label,
    pairedAt: new Date().toISOString(),
    hostId: record.HostID, systemBuid: record.SystemBUID,
    rootCertificate: new TextDecoder().decode(identity.rootCertificate),
    hostCertificate: new TextDecoder().decode(identity.hostCertificate),
    deviceCertificate: new TextDecoder().decode(identity.deviceCertificate),
    rootPrivateKey: identity.rootPrivateKey, hostPrivateKey: identity.hostPrivateKey
  }));
}

export class TrustedDevice {
  constructor({ serialNumber, label, pairedAt }) {
    this.serialNumber = serialNumber;
    this.label = label;
    this.pairedAt = pairedAt;
    Object.freeze(this);
  }
}

const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function performPair(mux, connection, serial, storage, label, emitState) {
  const keyResponse = await mux.lockdownRequest(connection, { Label: label, Request: "GetValue", Key: "DevicePublicKey" });
  if (keyResponse.Error) throw new Error(`GetValue(DevicePublicKey): ${keyResponse.Error}`);
  if (!(keyResponse.Value instanceof Uint8Array)) throw new Error("The iPhone did not return DevicePublicKey data.");

  const identity = await generatePairingIdentity(keyResponse.Value);
  const record = {
    DeviceCertificate: identity.deviceCertificate,
    HostCertificate: identity.hostCertificate,
    HostID: crypto.randomUUID().toUpperCase(),
    RootCertificate: identity.rootCertificate,
    SystemBUID: crypto.randomUUID().toUpperCase()
  };
  const request = {
    Label: label,
    PairRecord: record,
    Request: "Pair",
    ProtocolVersion: "2",
    PairingOptions: { ExtendedPairingErrors: true }
  };

  const deadline = Date.now() + 90_000;
  let pendingEmitted = false;
  while (Date.now() < deadline) {
    const response = await mux.lockdownRequest(connection, request);
    const pairingError = `${response.Error || ""}${response.ErrorDescription || ""}`.toLowerCase().replace(/[^a-z]/g, "");
    if (pairingError === "pairingdialogresponsepending") {
      if (!pendingEmitted) {
        pendingEmitted = true;
        emitState("pending", response);
      }
      await wait(750);
      continue;
    }
    if (pairingError === "userdeniedpairing") {
      emitState("declined", response);
      return { state: "declined", serialNumber: serial, response };
    }
    if (response.Error) {
      throw new Error(`Pairing failed: ${response.Error}${response.ErrorDescription ? ` — ${response.ErrorDescription}` : ""}`);
    }
    // iOS 5+ commonly omits Result; matching Request with no Error is success.
    if (response.Request !== "Pair" || (response.Result && response.Result !== "Success")) {
      throw new Error(`Unexpected Pair response: ${JSON.stringify(response)}`);
    }
    saveIdentity(storage, label, serial, identity, record);
    emitState("accepted", response);
    return { state: "accepted", serialNumber: serial, response };
  }
  throw new Error("Timed out waiting for a response to the iPhone pairing dialog.");
}

async function connectAndPair(client) {
  const connection = await connectToLockdown(client);
  return performPair(connection.mux, connection.connection, connection.serialNumber, client.storage, client.label, (state, response) => client.emitPairPromptState(state, response));
}

async function connectToLockdown(client, requestedSerial) {
  if (!client.usb) throw new Error("WebUSB is unavailable. Run this on a supported browser or a secure context.");
  if (client.device) {
    try { await client.device.close(); } catch {}
    client.device = null;
  }
  // Keep the chooser broad: serialNumber is not reliably exposed by WebUSB
  // device choosers. Verify it after the user selects the device instead.
  const device = await client.usb.requestDevice({ filters: [{ vendorId: APPLE_VENDOR_ID }] });
  client.device = device;
  const serialNumber = cleanUsbString(device.serialNumber);
  if (requestedSerial && serialNumber !== requestedSerial) {
    throw new Error(`Selected iPhone serial ${serialNumber} does not match ${requestedSerial}.`);
  }
  await device.open();

  const configuration = device.configurations.find(item => item.interfaces.some(group => group.alternates.some(alternate =>
    alternate.interfaceClass === 0xff && alternate.interfaceSubclass === 0xfe && alternate.interfaceProtocol === 0x02
  )));
  if (!configuration) throw new Error("No Apple mux configuration was exposed.");
  if (!device.configuration || device.configuration.configurationValue !== configuration.configurationValue) {
    await device.selectConfiguration(configuration.configurationValue);
  }
  const candidate = device.configuration.interfaces.flatMap(group => group.alternates.map(alternate => ({ group, alternate }))).find(({ alternate }) =>
    alternate.interfaceClass === 0xff && alternate.interfaceSubclass === 0xfe && alternate.interfaceProtocol === 0x02
  );
  await device.claimInterface(candidate.group.interfaceNumber);
  const input = candidate.alternate.endpoints.find(endpoint => endpoint.type === "bulk" && endpoint.direction === "in");
  const output = candidate.alternate.endpoints.find(endpoint => endpoint.type === "bulk" && endpoint.direction === "out");
  if (!input || !output) throw new Error("Apple mux bulk endpoints were not exposed.");
  const mux = new AppleMux(device, input.endpointNumber, output.endpointNumber);
  await mux.initialise();
  const connection = await mux.connect(LOCKDOWN_PORT);
  const query = await mux.lockdownRequest(connection, { Label: client.label, Request: "QueryType" });
  if (query.Type !== "com.apple.mobile.lockdown") throw new Error(`Unexpected QueryType response: ${JSON.stringify(query)}`);
  return { mux, connection, serialNumber, device };
}

export class USBMux extends EventTarget {
  constructor(options = {}) {
    super();
    this.usb = options.usb ?? globalThis.navigator?.usb;
    this.storage = options.storage ?? globalThis.localStorage;
    this.label = options.label ?? globalThis.location?.host ?? "usbmux.js";
    this.device = null;
    this.isPaired = false;
    this.pairPromptStateChanged = null;
    this.pairingPromise = null;
  }

  emitPairPromptState(state, response) {
    this.isPaired = state === "accepted";
    const data = { state, response };
    const event = new Event("pairPromptStateChanged");
    Object.defineProperty(event, "detail", { value: data, enumerable: true });
    this.dispatchEvent(event);
    if (typeof this.pairPromptStateChanged === "function") this.pairPromptStateChanged(data);
  }

  async getTrustedDevices() {
    if (!this.storage) return [];
    const devices = [];
    const prefix = "usbmux-pairing:";
    for (let index = 0; index < this.storage.length; index += 1) {
      const key = this.storage.key(index);
      if (!key?.startsWith(prefix)) continue;
      try {
        const record = JSON.parse(this.storage.getItem(key));
        if (record?.serialNumber) devices.push(new TrustedDevice(record));
      } catch {}
    }
    return devices;
  }

  async removeTrustedDevice(deviceOrSerial) {
    const serial = deviceOrSerial instanceof TrustedDevice ? deviceOrSerial.serialNumber : deviceOrSerial;
    if (typeof serial !== "string" || !serial) throw new TypeError("Expected a device serial number or TrustedDevice.");
    if (!this.storage) return false;
    const key = identityKey(this.label, serial);
    const saved = this.storage.getItem(key);
    if (!saved) return false;
    const stored = JSON.parse(saved);
    const link = await connectToLockdown(this, serial);
    const pairRecord = {
      DeviceCertificate: new TextEncoder().encode(stored.deviceCertificate),
      HostCertificate: new TextEncoder().encode(stored.hostCertificate),
      HostID: stored.hostId,
      RootCertificate: new TextEncoder().encode(stored.rootCertificate),
      SystemBUID: stored.systemBuid
    };
    try {
      const response = await link.mux.lockdownRequest(link.connection, {
        Label: this.label,
        PairRecord: pairRecord,
        Request: "Unpair",
        ProtocolVersion: "2"
      });
      if (response.Error) throw new Error(`Unpair failed: ${response.Error}`);
    } finally {
      try { await link.device.close(); } catch {}
      this.device = null;
    }
    this.storage.removeItem(key);
    this.isPaired = false;
    return true;
  }

  async pair() {
    if (this.pairingPromise) return this.pairingPromise;
    this.isPaired = false;
    this.emitPairPromptState("started");
    this.pairingPromise = connectAndPair(this);
    try {
      return await this.pairingPromise;
    } catch (error) {
      this.emitPairPromptState("error", { message: error.message, error });
      throw error;
    } finally {
      if (this.device) {
        try { await this.device.close(); } catch {}
        this.device = null;
      }
      this.pairingPromise = null;
    }
  }
}

export default USBMux;
