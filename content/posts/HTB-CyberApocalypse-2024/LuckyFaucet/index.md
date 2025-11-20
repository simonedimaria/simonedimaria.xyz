---
date: 2024-03-09T00:00:00+01:00
title: HTB CyberApocalypse 2024 - LuckyFaucet [Author Writeup]
summary: Author writeup for the "LuckyFaucet" easy blockchain challenge from CyberApocalypse CTF 2024.
categories: ["blockchain"]
difficulty: "easy"
tags: ["authored", "unsafe-casting", "integer-underflow"]
showHero: true
---

# LuckyFaucet

> Date: 9<sup>th</sup> March 2024 \
Challenge Author: <font color=#1E9F9A>perrythepwner</font> \
Difficulty: <font color=lightgreen>Easy</font> \
Category: <font color=orange> Blockchain</font>

## TL;DR

- The challenge consists in draining a generous faucet by exploiting an unsafe casting from `int64` to `uint64` in Solidity 0.7.6 (latest Solidity version before 0.8.0 breaking changes of native integer overflow checks) that causes an integer underflow in case of negative bounds set.

## Description

> I left a faucet along the path for adventurers capable of overcoming the first hurdles. It should provide enough resources for all players... hoping that someone won't be able to break it and leave none to others.

## Skills Required

- Smart contract interaction.

## Skills Learned

- Unsafe casting for contracts before Solidity 0.8.0
- Integer underflows/overflows for contracts before Solidity 0.8.0

## Challenge scenario

In this easy blockchain challenge we're given only one target address to interact with, that is the LuckyFaucet contract. The contract is a simple faucet that gives out random quantity of ETH within a given range.  
This range can be modified by the preferences & needs of the player, both `lowerBound` and `upperBound`.  
The quantity of ETH given out is determined by the previous block hash converted in `uint256`, which is not a real source of randomness. However, since the contracts sets 100M Wei (0.0000000001 ETH) as the maximum output value, and we need at least 10 ETH to solve the challenge, we don't really care about "hacking" the randomness, since it would require 100_000_000_000 function calls to get to 10 ETH with 100M wei for each output.

## Solution

Searching for low hanging fruit vulnerabilities in the contract that would allow us to send us more ETH than the contract allows, we will find nothing. On the other hand, the contract does not have many lines, which means that perhaps we should sharpen our sight a little more and not take everything for granted.  
In fact, we will notice that not all the integer types used in the contract are of the same size (256 bits).    
Because, as the comments explains, 64 bits are enough to calculate the output value, since the maximum integer rapresentable by `uint64` is ~18 ETH and the faucet "will never worry about sending more".  
But first of all, we note also that not all integers are `uint`, in fact there are also `int` (signed integers). This means that they allow negative values ​​to be represented.  
Moreover, we note how - in a somewhat hidden way - an `int64` is cast to `uint64` at Line 28; and what happens when a negative value represented by a signed integer is tried to be represented by an unsigned integer?  
It underflows. e.g.:  
```-1 in int64 == 2**64 - 1 in uint64```  
Which means that if we set bounds to negative values like:   
`upperBound = -1`  
`lowerBound = -2`  
We will have an underflow when the contract will try to cast `-1` or `-2` to `uint64` and it will be represented as `2**64 - 1` and `2**64 - 2` respectively, which is a little more than 18 ETH.  
Enough to solve the challenge.

## Exploitation

1) Set the bounds to negative values:
```sh
$ cast send --rpc-url $RPC_URL --private-key $PVK $TARGET "setBounds(int64,int64)" -- -2 -1
```

2) Drain the contract and win: 
```sh
$ cast send $TARGET "sendRandomETH()"  --rpc-url $RPC_URL --private-key $PVK
```

> HTB{1_f0rg0r_s0m3_U}