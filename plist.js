const encoder = new TextEncoder();

function escapeXml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function base64(bytes) {
  let result = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    result += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(result);
}

function valueXml(value) {
  if (value instanceof Uint8Array) return `<data>${base64(value)}</data>`;
  if (value instanceof ArrayBuffer) return `<data>${base64(new Uint8Array(value))}</data>`;
  if (typeof value === "boolean") return value ? "<true/>" : "<false/>";
  if (typeof value === "number") return `<integer>${value}</integer>`;
  if (typeof value === "string") return `<string>${escapeXml(value)}</string>`;
  if (Array.isArray(value)) return `<array>${value.map(valueXml).join("")}</array>`;
  if (value && typeof value === "object") {
    return `<dict>${Object.entries(value).map(([key, item]) => `<key>${escapeXml(key)}</key>${valueXml(item)}`).join("")}</dict>`;
  }
  throw new TypeError(`Unsupported plist value: ${value}`);
}

export function encodePlist(value) {
  return encoder.encode(`<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">${valueXml(value)}</plist>`);
}

function fromBase64(text) {
  const binary = atob(text.replace(/\s/g, ""));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function parseNode(node) {
  switch (node.tagName) {
    case "dict": {
      const result = {};
      const children = [...node.children];
      for (let i = 0; i < children.length; i += 2) result[children[i].textContent] = parseNode(children[i + 1]);
      return result;
    }
    case "array": return [...node.children].map(parseNode);
    case "string": return node.textContent;
    case "integer": return Number(node.textContent);
    case "data": return fromBase64(node.textContent);
    case "true": return true;
    case "false": return false;
    case "date": return new Date(node.textContent);
    default: throw new Error(`Unsupported plist element <${node.tagName}>`);
  }
}

export function decodePlist(bytes) {
  const text = new TextDecoder().decode(bytes);
  if (!text.trimStart().startsWith("<")) throw new Error("The phone returned a binary plist; this build expects lockdown XML responses.");
  const document = new DOMParser().parseFromString(text, "application/xml");
  const error = document.querySelector("parsererror");
  if (error) throw new Error(`Invalid plist XML: ${error.textContent}`);
  return parseNode(document.documentElement.firstElementChild);
}
