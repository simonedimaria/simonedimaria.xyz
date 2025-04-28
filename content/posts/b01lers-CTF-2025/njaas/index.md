---
date: 2025-04-25T00:00:00+01:00
title: njaas
summary: Another view on how the popular CVE-2025-29927 NextJS middleware bypass could still be exploited.
categories: ["web"]
difficulty: "medium"
tags: ["NextJS", "CVE-2025-29927"]
showHero: false
---


## TL;DR
The `proxy/app.py` server is a simple reverse proxy that startups a `NextJS` app instance and forwards requests to it. This proxy is vulnerable to set an env var with length constraints, without controlling the value. This can be abused to set the `NEXT_PRIVATE_TEST_HEADERS` env var on the `NextJS` app and make the `CVE-2025-29927` exploit possible again.


## Description
> I heard about some next.js cve issues recently, so I decided to provide next.js on a safe version for anyone!


## Challenge Scenario
Another week goes by, and again Next JS can't go 5 seconds without humiliating itself. Since the public disclosure of CVE-2025-29927, NextJS has caught the attention of many security researchers from all over the world, and in particular from CTF players. When I saw that this weekend too there was a challenge on NextJS I could NOT skip it, I needed a good laugh.  

![NextJS meme](./img/nextjs-meme.jpg)

At this point I don't know anymore who's the most bullied between NextJS and Bun.  

It was one of the first challenges I looked into, and after a few hours we got first blood :)  

![njaas first blood](./img/njaas-firstblood.png)

At the end of the event, it was the least solved web challenge along with `web/musicplayer` (which we also solved :p) so here I am writing a writeup for it.

## Challenge Scenario (for real this time)
The challenge setup is pretty simple, there's a `proxy/app.py` server that acts as instancer and reverse proxy for the NextJS app that can be launched via the `/start` endpoint. The NextJS app is pretty much just a template that hardcodes the flag in the html at `/admin/flag`, with the following middleware:

**middleware.ts**
```ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

// don't want just anyone getting the flag ⭐️
export function middleware(request: NextRequest) {
  return NextResponse.redirect(new URL('/', request.url));
}

export const config = {
  matcher: '/admin/:path*'
}
```

As simple as it gets, the middleware just redirects any request to `/admin/*` back to the homepage. Or I'd say, how it should have been (right nextjs?). Clearly the goal here is to bypass the middleware to get the flag, which instantly made me think of CVE-2025-29927. 

Any route-based bypass could also have worked obviously, it may happen with some `matcher` misconfigurations for example. Something that could also work is any type of path normalization issue that is then used for an internal rewrite (NextResponse.rewrite).  
Interestingly enough, while I was fuzzing for interesting env vars, i found the `skipMiddlewareUrlNormalize` config (tracked by the [__NEXT_NO_MIDDLEWARE_URL_NORMALIZE env var at build time](https://github.com/vercel/next.js/blob/f0f0e4bf5aa67bfed0b7bbf87a2ebe75b02a54bb/packages/next/src/build/webpack/plugins/define-env-plugin.ts#L234-L235)), that [disables URL normalizations in middleware](https://nextjs.org/docs/app/building-your-application/routing/middleware#advanced-middleware-flags)... aand why is that interesting? NextJS automatically generates internal JSON endpoints for SSR pages, e.g. `/_next/data/<build-id>/admin/flag.json` for `/admin/flag` endpoint. These endpoints contain only the props needed for hydration or ISR, to avoid sending the full HTML each render. Moreover, these are the endpoints that are normalized by default, but that doesn't happens with `skipMiddlewareUrlNormalize`. In that case, a request to `/_next/data/<build-id>/admin/flag.json` will effectively bypass the middleware `/admin/*` matcher.

The challenge was running an hardcoded version of NextJS 15.2.3, meaning that the CVE-2025-29927 was not exploitable anymore directly.  
Fun fact: After CVE-2025-29927 was patched, i decided to take a look on how they implemented the fix. Initially I expected that they had completely revisited the middleware request handling model (because there's no way that's a good design model). Then I remembered that we are talking about NextJS and that in the meantime the vulnerability had gone around the world. It certainly couldn't be a quality patch to say the least.
In fact, that was the patch: https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2

The commit message alone doesn't inspire much confidence, it looks almost it's a routine dev fix and not a critical security patch. At that time i decided to take a closer look and so i found myself reading the NextJS source code at 3AM of a random Tuesday. In fact, I quickly realized that the "patch" wasn't actually a fix, but rather a workaround: `x-middleware-subrequest` was still allowed 