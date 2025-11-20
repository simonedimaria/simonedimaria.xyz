---
date: 2024-03-09T00:00:00+01:00
title: HTB CyberApocalypse 2024 - Recovery [Author Writeup]
summary: Author writeup for the "Recovery" very-easy blockchain challenge from CyberApocalypse CTF 2024.
categories: ["blockchain"]
difficulty: "very-easy"
tags: ["authored", "warmup", "bitcoin", "electrum"]
showHero: true
---

# Recovery

> Date: 9<sup>th</sup> March 2024 \
Challenge Author: <font color=#1E9F9A>perrythepwner</font> \
Difficulty: <font color=yellow>Very Easy</font> \
Category: <font color=orange> Blockchain</font>

## TL;DR

- The challenge consist in recovery stolen BTC funds given an Electrum seed phrase in an hacked ssh instance.

## Description

> Hacker, help!
During the war our infrastructure was compromised as were the private keys to our Bitcoin wallet that we kept.  
We managed to track the hacker and were able to get some SSH credentials into one of his personal cloud instances, can you try to recover my Bitcoins?  
`satoshi:L4mb0Pr0j3ct`  
NOTE: Network is regtest, check connection info in the handler first.  

## Skills Required

-  None

## Skills Learned

- Bitcoin wallets
- Bitcoin regtest network
- Wallets seed phrases
- Electrum wallet setup & interaction
- Sending Bitcoins

## Enumeration

We must find a way to recover the funds that were stolen from us.  
We have been given an ssh instance that we can access with the credentials:
`satoshi:L4mb0Pr0j3ct`

![SSH access](./assets/ssh_access.png)

Once we login in we'll note a `electrum-wallet-seed.txt` file inside the home directory.
The players can google something like "electrum wallet seed" and find some interesting links:
- [Electrum Seed Version System](https://electrum.readthedocs.io/en/latest/seedphrase.html)
- [Restoring your standard wallet from seed - Bitcoin Electrum](https://bitcoinelectrum.com/restoring-your-standard-wallet-from-seed/)
- https://bitcoinelectrum.com/creating-an-electrum-wallet/

With these links alone the player will learn what's a Bitcoin wallet, how to create/load it, what's BIP39 etc.

## Solution

### Wallet Recovery

0) Install Electrum wallet client

![https://electrum.org/#download](./assets/electrum_download.png)

1) Start the client in `regtest` mode as the description suggest
![](./assets/electrum_newwallet.png)
2) Standard wallet --> I already have seed --> insert the seed phrase found in the ssh instance
![](./assets/electrum_importseed.png)

3) Change network to the Electrum server provided to connect to the blockchain
![](./assets/electrum_server.png)

We could also started Electrum with the correct server from the cli, with:
 `./electrum-4.4.6-x86_64.AppImage --regtest --oneserver -s 0.0.0.0:50001:t`

4) Connect to Challenge Handler to get the flag
![](./assets/challenge_handler.png)

5) Send back the Bitcoin to the given address.
![](./assets/sending_btc_back.png)
![](./assets/btc_sent.png)
![](./assets/flag.png)

> HTB{n0t_y0ur_k3ys_n0t_y0ur_c01n5}