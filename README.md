# usbmux.js

Browser-side iPhone pairing over WebUSB. Although distributed as an npm
package, it must execute in a WebUSB-capable browser secure context; Node.js
does not provide `navigator.usb`.

## Table of Contents

- [Examples](#examples)
  - [Pairing Device](#pairing-device)
  - [Getting a list of TrustedDevices](#getting-a-list-of-trusteddevices)
  - [Forgetting a TrustedDevice](#forgetting-a-trusteddevice)
- [License](#license)

## Examples

### Pairing Device

```js
import USBMux from "usbmux.js";

const mux = new USBMux();

mux.addEventListener("pairPromptStateChanged", event => {
  console.log(event.detail.state); // started, pending, declined, accepted or error
});

const button = document.querySelector("#pair");
button.addEventListener("click", async () => {
  const result = await mux.pair();
  console.log(result.state, result.serialNumber, mux.isPaired);
});
```

### Getting a list of TrustedDevices

```js
import USBMux from "usbmux.js";

const mux = new USBMux();

const devices = await mux.getTrustedDevices();
// {serialNumber, label, pairedAt}

console.log(devices);
```

### Forgetting a TrustedDevice

```js
import USBMux from "usbmux.js";

const mux = new USBMux();

const devices = await mux.getTrustedDevices();

if (devices.length > 0) {
  await mux.removeTrustedDevice(devices[0]);
}
```

## License
[MIT license](LICENSE)