---
title: The illusion of Security in CSRF Defense
Date: 2025-05-01
image: avatar.png
autoimage: yes
description: Dexter
Categories: Web Security
author: Dexter
comments: true

---

## SameSite Cookie Restrictions

The `SameSite` attribute is a browser security mechanism that controls when cookies are sent with cross-site requests. It's designed to prevent certain types of cross-site attacks, including CSRF, information leaks, and even some Cross-Origin Resource Sharing (CORS) exploits.

By setting the `SameSite` attribute, you define whether a cookie should be sent in **first-party** or **cross-site** contexts. There are three possible values:

### SameSite=Strict

- Cookies are **only** sent if the request originates from the same site (first-party context).
    
- If a user follows a link from another website, the browser **will not** include the cookie in the initial request.
    
- This offers the **strongest CSRF protection**, but may break legitimate workflows that rely on cross-site logins or redirections.


### SameSite=Lax

- Cookies are included in:
    
    - **Top-level navigations** (e.g., clicking a link)
        
    - **Safe HTTP methods** like `GET`
        
- Cookies are **not** included in cross-site `POST`, `PUT`, or `DELETE` requests.
    
- This strikes a balance between usability and security, and is now the default in many modern browsers.
    

### SameSite=None

- Cookies are sent in **all contexts**, including cross-site requests.
    
- To use `SameSite=None`, you **must** also set the `Secure` attribute (i.e., HTTPS).
    
- This disables SameSite protection entirely and should only be used when absolutely necessary (e.g., for third-party services).
    
Below is a snippet of how we can set this cookies in our express app.

<details>
<summary> Snippet </summary>

```javascript
const express = require("express");
const app = express();

app.get("/set-cookie", (req, res) => {
  // SameSite=Strict
  res.cookie("strictCookie", "value1", {
    sameSite: "Strict",
    httpOnly: true,
    secure: true,
  });
  //Samesite=Lax
  res.cookie("laxCookie", "value2", {
    sameSite: "Lax",
    httpOnly: true,
    secure: true,
  });
  //SameSite= 'None'
  res.cookie("noneCookie", "value3", {
    sameSite: "None",
    httpOnly: true,
    secure: true,
  });

  res.send("Cookies set with SameSite attributes.");
});

app.listen(3000, () => {
  console.log("Server is running");
});
```

</details>

## Bypassing SameSite=Lax with GET Requests

Despite the protection offered by `SameSite=Lax`, many applications still expose themselves by accepting `GET` requests for sensitive actions.

Here’s why that matters:

- With `SameSite=Lax`, a browser **will include cookies** on cross-site `GET` requests **if** they are the result of a top-level navigation (like clicking a link).
    
- If a vulnerable application allows sensitive actions via `GET` (e.g., fund transfers, account changes), an attacker can exploit this by tricking the user into clicking a malicious link.
    

> 💥 **Example:**  
> If `/transfer?amount=100&to=attacker` performs a real money transfer, and the user is authenticated, clicking a link can trigger the action **without any CSRF token** — even with SameSite=Lax enabled.

### The Problem

In our example let us set the transfer page to use `GET` 

```javascript
app.get("/transfer", (req, res) => {
  const username = req.cookies.session;

  if (!username || !users[username]) {
    return res.redirect("/?error=session_expired");
  }

  const amount = parseInt(req.query.amount);
  const to = req.query.to;

  if (users[username].balance >= amount) {
    users[username].balance -= amount;
    return res.redirect("/dashboard?success=transfer_complete");
  }

  res.redirect("/dashboard?error=insufficient_funds");
});

```

In our URL we are gonna add `/transfer?amount=1000&to=bob`

![GET](https://i.ibb.co/hRGJ2pyD/image.png)

After adjusting our vulnerable app to accept a `GET` request at the `/transfer` endpoint, we introduced a subtle but serious vulnerability. Let’s break down **why this seemingly innocent change allows a full CSRF attack to succeed.**

1. Sensitive Actions Over GET

The `/transfer` endpoint now accepts `GET` requests to move money between accounts, like this:

`GET /transfer?amount=1000&to=attacker`

This is inherently unsafe. According to web standards, `GET` requests should be used for retrieving data — **not performing actions**. Making changes via `GET` opens the door to abuse, especially when combined with...

2. Automatic Cookie Sending

When a user is logged in, their browser automatically sends cookies — like the session cookie — with any request to your site. That includes requests triggered **from another site**, unless restricted.

This means an attacker can craft a malicious link like:

`<img src="http://bank.com/transfer?amount=1000&to=attacker">`

If the victim is logged in and views this HTML (e.g. in a malicious forum post or phishing email), their browser sends the request **with the session cookie**, making it indistinguishable from a legitimate request.

 3. SameSite=Lax Isn’t Enough

 The default behavior is usually `SameSite=Lax`, which **blocks cookies on most cross-site POST requests** — but **still allows them on GET requests** that result from top-level navigation (like clicking a link or loading an image).

Since our exploit uses a simple `GET` request, and our cookies use `SameSite=Lax`, the attack goes through without a hitch.

### The Fix

Now that we have seen how dangerous it is to allow sensitive operations over `GET` requests, we can talk about how to properly prevent this kind of vulnerability. 

1. Never perform state changing actions over GET
`GET` requests are meant for reading data, and not modifying data. Instead we need to use `POST` , `PUT` or `DELETE` for operations that do change state, this includes transferring money, updating profiles or submitting forms. 

```javascript
app.post('/transfer', ... )
```

2. Validating CSRF tokens on state-changing requests

For routes that modify data, a CSRF token could be generated on the server and validate it when a request is made. This means that even if cookies are sent, the attacker won't have access to the CSRF token which is stored in the page content or local storage and not in the cookies. 

```javascript
if (req.body.csrfToken !== req.cookies.csrfToken) {
	return res.status(403).send("Validation failed");
}
```

## Bypassing Samesite Cookie Restrictions with Method Override

Some modern web frameworks provide support for **HTTP method overriding**—a feature that allows clients to "simulate" methods like `PUT`, `DELETE`, or even `GET` using alternative means, typically through hidden form fields or custom headers. While this feature helps in environments that only support `GET` and `POST`, it can inadvertently open up CSRF vulnerabilities when combined with `SameSite=Lax` cookie policies.

An attacker can exploit this behavior by crafting a malicious form that appears to submit a `POST` request but actually overrides the method to `GET` or another sensitive method using a special parameter. If the backend trusts this override and does not validate CSRF tokens consistently across all accepted methods, the attacker may successfully execute unauthorized actions on behalf of the victim.

The following table outlines some common frameworks that support method override and how this feature can be used:

| **Framework**         | **Override Parameter**           | **Allowed Method**            | **Example Value**     |
|-----------------------|----------------------------------|-------------------------------|------------------------|
| **Symfony**           | `_method`                        | Any (`GET`, `PUT`, `DELETE`)  | `_method=GET`         |
| **Laravel**           | `_method`                        | `PUT`, `DELETE`, `PATCH`      | `_method=DELETE`      |
| **Ruby on Rails**     | `_method`                        | `PUT`, `DELETE`, `PATCH`      | `_method=PUT`         |
| **Express (Node.js)** | Custom (`_method`) via middleware| Any method allowed by app     | `_method=GET`         |
| **Django**            | Often custom, depends on setup   | Depends on implementation     | `_method=DELETE`      |
| **Spring MVC (Java)** | `X-HTTP-Method-Override` (Header)| `PUT`, `DELETE`, etc.         | `X-HTTP-Method-Override: DELETE` |
### Exploit

In a typical CSRF attack, the attacker tricks a victim’s browser into making an unwanted request to a trusted site where the user is already authenticated. When frameworks support HTTP method overrides—such as using a hidden `_method` field in a form—the attacker can abuse this behavior to change the request’s method behind the scenes.

Imagine a scenario where the server expects a `GET` request to view user information but a `POST` request to perform a sensitive action like transferring money. If the server accepts a `POST` request containing `_method=GET` and routes it as a `GET` request without re-validating CSRF tokens or access controls, this can be exploited.

The attacker can craft a malicious HTML page (e.g., `mal.html`) with a hidden form like:

```html
<form action="https://bank.example.com/transfer" method="POST">     
<input type="hidden" name="_method" value="GET">     
<input type="hidden" name="amount" value="1000">     
<input type="hidden" name="to" value="attacker">     
<button> Click here to claim your prize</button> </form>
```

If the victim is logged in and clicks the button, the browser sends a `POST` request, which the server may interpret as a `GET` request due to the `_method` override. Because `SameSite=Lax` cookies allow `GET` cookies during top-level navigation, the session cookie will be included—resulting in a CSRF attack without the need for a token.

This illustrates how method override features—if not properly secured—can become a powerful tool in the hands of attackers.

## Bypassing SameSite restrictions using on-site gadgets

While `SameSite=Strict` cookies offer the strongest defense against cross-site request forgery, they can still be bypassed in certain situations using what’s known as **on-site gadgets**.

One such gadget is a **client-side redirect** that dynamically constructs a redirection URL using attacker-controlled input. This redirect is typically triggered by a user interacting with the attacker’s site, but the actual request is executed by the vulnerable website itself, within the same origin.

```js
// Example of a vulnerable redirect handler 
app.get('/redirect', (req, res) => {     
	const target = req.query.url;     
	res.redirect(target); 
});
```

If an attacker tricks a logged-in user into visiting a link like this:

`https://vulnerable-site.com/redirect?url=/transfer?amount=1000&to=hacker`

…the browser first sends a request to `/redirect` (a same-origin endpoint), which immediately redirects to `/transfer?amount=1000&to=hacker`. Since both requests are to the same site, **the browser considers this a same-site request**, even though it originated from a cross-site context.

> **As far as browsers are concerned**, these client-side redirects aren’t really redirects at all. The resulting request is treated as an ordinary, standalone request—**a same-site request**. As a result, all site cookies, including `SameSite=Strict` ones, are included automatically.

This behavior opens the door to bypassing cookie protections. If the redirect can be used to trigger a sensitive action (like a fund transfer), and the application doesn’t verify additional CSRF tokens or headers, then a successful CSRF exploit can be executed.

> ⚠️ **Important:** This bypass technique **does not** work with server-side redirects. In that case, browsers recognize that the request originated from a different site and still enforce `SameSite` restrictions when following the redirect.

![well](https://i.ibb.co/39wB4s26/image.png)


## Bypassing SameSite restrictions via vulnerable sibling domains
Here we need to explain the difference between Same-Site and same-origin. This are frequently cited but often misunderstood terms. 

1. Origin

An **origin** is defined as the combination of:

- The **scheme** (e.g. `http` or `https`)
    
- The **hostname** (domain)
    
- The **port**
    

For example, given the URL:

`https://www.example.com:443/foo`

The **origin** is:

`https://www.example.com:443`

If any of these components (scheme, hostname, or port) differ, the origin is considered different.

2. Site

A **site** is a broader concept. It includes:

- The **scheme** (`http` or `https`)
    
- The **top-level domain (TLD)** and the **immediate subdomain to its left** — typically referred to as the **registrable domain**
    

Using the same URL `https://www.example.com:443` The **site** is `https://example.com`

This means:

- `https://shop.example.com`
    
- `https://admin.example.com`
    
- `https://blog.example.com`
    

...are all considered part of the **same site** as `https://www.example.com`.

However, they are **not** part of the same **origin**, since their hostnames differ.

- **Same-Origin Policy (SOP)** is a strict browser security model that prevents scripts from one origin from accessing data on another.
    
- **SameSite cookies** use the _site_ definition to decide whether to include cookies in cross-site requests — which is a looser definition than SOP.

### Bypass

When attempting to bypass SameSite cookie restrictions, it's important to remember that **a request can still be considered same-site even if it's issued cross-origin** — as long as it originates from a domain under the same registrable site (e.g. `shop.example.com` and `admin.example.com` are siblings of `example.com`).

This means that vulnerabilities in **any sibling domain** — not just the main application — can be used as a foothold for launching cross-site attacks. For example:

- A **stored XSS** in a sibling subdomain can be used to craft requests to `secure.example.com`, which will include session cookies due to the browser considering the request same-site.
    
- A **malicious redirect** or DOM-based open redirect in a sibling domain may allow the attacker to bounce through and reach the secure domain with all cookies intact.

## Bypassing SameSite Lax restrictions with newly issued cookies

Modern browsers like Chrome apply `SameSite=Lax` restrictions to cookies by default. This means cookies are typically not sent along with cross-site `POST` requests, offering some protection against CSRF attacks. However, there is a subtle and critical exception.

To maintain compatibility with common authentication flows such as Single Sign-On (SSO), Chrome does **not** enforce `Lax` restrictions for the **first 120 seconds** after a cookie is initially set. During this **two-minute window**, newly issued cookies are treated as if they had no SameSite restrictions, and will be included in top-level `POST` requests—even if they were not explicitly marked with `SameSite=None`.

This behavior introduces a short but significant vulnerability window where cross-site `POST` requests can succeed, effectively bypassing Lax protections.

> Note: This two-minute exception **does not apply** to cookies that are **explicitly** set with `SameSite=Lax`. It only affects cookies that rely on the browser's default behavior.

### Real-world Example

A notable case exploiting this behavior was demonstrated in [this blog post by Teddy Katz](https://blog.teddykatz.com/2019/11/05/github-oauth-bypass.html), where the author used this timing window to bypass GitHub’s OAuth flow, exploiting the moment just after a session cookie was issued.

### Exploit

To exploit the two-minute window, the attacker needs to refresh the victim’s cookies via a **top-level navigation**, ensuring that the cookies tied to the current OAuth session are sent along with the request. This introduces an extra challenge: the user must be redirected back to the attacker's site to initiate the actual exploit.

An alternative approach is to **trigger the refresh in a new tab**, preserving the victim’s current page while preparing the exploit in the background. However, this method comes with a limitation—**modern browsers typically block pop-ups** unless they are the result of **direct user interaction**, such as clicking a button or link.

## Bypassing Referer-based CSRF Defenses

Some applications attempt to mitigate CSRF by validating the HTTP `Referer` header. If the header indicates that the request came from the same domain, the request is allowed. However, this approach is **inherently flawed** and prone to multiple **bypass techniques**.

### Suppressing the Referer Header

Many applications only validate the `Referer` header when it is present but **skip validation altogether if it’s missing**. This opens the door to easy bypasses. An attacker can intentionally cause the browser to omit the header using:

`<meta name="referrer" content="never">`

This directive instructs the browser **not to send a `Referer` header** on any outgoing request, effectively bypassing any logic that requires it for validation.

### Weak Validation Logic

Other applications do validate the `Referer` header but do so **in an insecure way**:

- **Prefix-based validation**:  
    If the application checks that the domain _starts with_ the trusted domain:
    
    `http://vulnsite.com.attackersite.com/csrf-attack`
    
    The attacker controls a subdomain like `vulnsite.com.attackersite.com`, which **passes the naive check** even though it’s not part of the legitimate site.
    
- **Substring-based validation**:  
    If the application only checks that the `Referer` **contains** its domain name:

    `http://attacker-website.com/csrf-attack?vulnerable-website.com`
    
    The trusted domain appears somewhere in the URL string, even though the request comes from a malicious origin.


## Protocol-Level SameSite BlindSpots

While GET-based attacks exploit SameSite=Lax's navigation allowances, modern web applications introduce subtler vulnerabilities through protocol-level quirks—particularly in WebSockets and CORS configurations. These bypasses often work even when traditional CSRF defenses appear intact.

### Websockets Silent SameSite Override

Unlike HTTP, WebSocket connections (`ws://`/`wss://`) **ignore SameSite cookie policies entirely**. Browsers will automatically attach cookies (including those marked `SameSite=Lax`) if the domain matches, enabling stealthy CSRF attacks.

Here is a sample websocket in Node.js

```js
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 3001 });

// Mock user database
const accounts = {
  alice: { balance: 5000, sessionCookie: 'alice_session=123' }
};

wss.on('connection', (ws, req) => {
  const cookies = req.headers.cookie;
  
  ws.on('message', (data) => {
    const { cmd, amount, to } = JSON.parse(data);
    
    if (cmd === 'transfer' && cookies.includes('alice_session')) {
      accounts.alice.balance -= amount;
      ws.send(`Transferred $${amount} to ${to}. New balance: $${accounts.alice.balance}`);
    }
  });
});
```

The attack flow is very much similar to what we have discussed so far, where the victim will login to the bank account, the attacker will then lure the victim with an malicious page. The browser ultimately attaches `SameSite=Lax` to the WebSocket handshake. 

The exploit would look something like. 

```html
<!doctype html>
<html>
  <body>
    <h1>Click to claim your prize!</h1>
    <button onclick="attack()">Claim Now</button>

    <script>
      function attack() {
        const ws = new WebSocket("ws://localhost:3001");

        ws.onopen = () => {
          console.log("WebSocket connected! Sending attack...");
          ws.send(
            JSON.stringify({
              cmd: "transfer",
              amount: 1000,
              to: "attacker",
            }),
          );
        };

        ws.onmessage = (e) => {
          console.log("Server response:", e.data);
          alert("Attack result: " + e.data);
        };

        ws.onerror = (e) => {
          console.error("WebSocket error:", e);
          alert("Error: Open DevTools (F12) and check Console");
        };
      }
    </script>
  </body>
</html>
```

I added some debugging text as this was a bit harder to make it work locally but we did ultimately achieve the goal of transferring the funds. 

![poc](https://i.ibb.co/YB7jhFS7/image.png)


### CORS (Cross origin resource sharing) bypasses for CSRF attacks

CORS is designed to restrict cross-origin HTTP requests, but misconfigurations can enable CSRF exploits a high possibility. Normally browsers block cross-origin `POST` requests with cookies do to the `SameSite=Lax` restriction, but a misconfiguration could be set where the wildcard `*` is used that would allow all. 

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

Real world bypass techniques would include: 
#### Exploiting `null` origin 

This is where some APIs would allow allow `null` origins and are common in local contexts.

```js
app.use(cors({ origin: 'null', credentials: true }));
```

In this scenario the attacker could craft something like:

```html
<iframe sandbox="allow-scripts" srcdoc='
  <script>
    fetch("https://bank.com/transfer", { 
      method: "POST", 
      credentials: "include" 
    });
  </script>
'></iframe>
```

#### Regex Bypasses

This is where a weak regex is used in origin validation. 

```js
app.use(cors({ origin: /bank\.com$/, credentials: true }));
```

Here an attacker could craft something like: 

```js
fetch('https://bank.com/transfer', {
  headers: { 'Origin': 'https://bank.com.attacker.com' },  // Matches regex!
  credentials: 'include'
});
```

Where as long as the regex does match in the slightest a bypass works out. 

To secure CORS configuration, one would only add an explicit allowlist that will only allow a particular origin. Also cookie forwarding could be blocked by setting `credentials: false`. Here is a snippet. 

```js
app.use(cors({
  origin: 'https://trusted.com',  // Explicit allowlist
  credentials: false,             // Block cookie forwarding
  methods: ['GET']                // Restrict risky methods
}));
```

## Conclusion
While modern defenses like CSRF tokens and SameSite cookie attributes have significantly raised the bar for CSRF attacks, they are far from foolproof. As we’ve explored, subtle implementation oversights, such as failing to validate tokens for GET requests or relying solely on browser-enforced restrictions, can create dangerous gaps in security. Attackers can exploit framework behaviors, method override gadgets, and even sibling domain vulnerabilities to sneak past seemingly solid defenses.

True protection against CSRF requires defense-in-depth. This includes proper token validation across all state-changing actions, rigorous origin checks, and a clear understanding of what SameSite actually protects — and what it doesn’t. Most importantly, security must be proactive, not reactive: understanding these nuances now can prevent costly compromises later.

## Resources

1. [SameSite Bypass](https://hazanasec.github.io/2023-07-30-Samesite-bypass-method-override.md/)
2. [SameSite Confusion](https://jub0bs/com/posts/2021-01-29-great-samesite-confusion)
3. [Portswigger](https://portswigger.net/web-security/learning-paths/csrf)
4. [Owasp](https://owasp.org/www-community/attacks/csrf)
5. [Cookies Explained](https://web.dev/articles/samesite-cookies-explained)

## Comments

{{< chat disqus_thread >}}

---
