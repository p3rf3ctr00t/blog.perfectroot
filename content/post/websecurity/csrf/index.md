---
title: Understanding CSRF
Date: 2025-04-28
image: avatar.png
autoimage: yes
description: Dexter
Categories: Web Security
author: Dexter
comments: true

---

## What is CSRF

**Cross-Site Request Forgery (CSRF)** is a web security vulnerability that allows an attacker to trick users into performing actions they didn't intend. It partially bypasses the browser’s **Same-Origin Policy**, which is meant to stop different websites from interfering with each other.

When a user is logged into a site, their browser automatically includes credentials like session cookies with any request to that site. Because of this, the web application can't always tell whether a request came from the user themselves or from an attacker trying to impersonate them.

One special type of CSRF attack is called **Login CSRF**. In this attack, an attacker tricks a user who is not logged in into unknowingly logging into an account the attacker controls. If the victim doesn't realize this, they might enter personal information into the account — information the attacker can later access along with the victim’s activity history.

In some cases, it’s even possible for attackers to **store** a CSRF attack directly on the vulnerable website itself. These are called **Stored CSRF** attacks. This can happen, for example, by inserting an `<img>` or `<iframe>` tag into a field that accepts HTML input — or by using a more advanced Cross-Site Scripting (XSS) attack to inject malicious content.

## How CSRF works
Imagine you’re logged into your online bank in one tab. In another tab, you visit a malicious website. Without you realizing it, that site secretly sends a money transfer request to your bank — and because you're already logged in, your bank thinks the request came from you.

![Path](https://i.ibb.co/jv8drXcY/image.png)

## When is a CSRF Attack Possible?

For a CSRF attack to succeed, three key conditions must be in place:

| Condition                     | What It Means                                                                             | Why It Matters for CSRF                                                                                     |
| :---------------------------- | :---------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------- |
| **Relevant Action**           | There’s an action the attacker wants to force (like a money transfer or password change). | The attacker needs a valuable action to exploit.                                                            |
| **Cookie-Based Session Only** | The site trusts session cookies to identify users, without any extra checks like tokens.  | The browser will automatically send the session cookie, making it easy for the attacker to act as the user. |
| **No Secret Parameters**      | The attacker can predict or guess all the request details needed to perform the action.   | If the request used unpredictable values (like CSRF tokens), the attack would fail.                         |
## Vulnerable Bank App: Setting the Stage for a CSRF Attack

To help you fully understand how a CSRF attack works in practice, I created a small demo application.  
This vulnerable app simulates a simple online banking system where users can log in, view their account balance, and transfer money.

It uses **cookie-based session handling** — and **no additional protections** like CSRF tokens — making it a perfect target for a CSRF attack.


<details>
<summary><strong> Click to expand code (app.js)</strong> </summary>

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const app = express();
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

// Add this middleware to set proper headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    next();
});

const users = {
    'alice': { password: 'password123', balance: 5000 },
    'bob': { password: 'securepass', balance: 2500 }
};

// Login route with proper redirect
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    
    if (user && user.password === password) {
        res.cookie('session', username, { 
            httpOnly: true,
            sameSite: 'Lax', // Changed from default for redirects to work
            path: '/'
        });
        return res.redirect('/dashboard');
    }
    res.status(401).send(`
        Invalid credentials! 
        <a href="/">Try again</a>
        <script>
            setTimeout(() => window.location = "/", 2000);
        </script>
    `);
});

// Dashboard with proper session checking
app.get('/dashboard', (req, res) => {
    const username = req.cookies.session;
    if (!username || !users[username]) {
        return res.redirect('/?error=session_expired');
    }
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>Welcome, ${username}!</h1>
            <h2>Balance: $${users[username].balance}</h2>
            
            <form action="/transfer" method="POST">
                <h3>Transfer Money</h3>
                <input type="number" name="amount" placeholder="Amount" required>
                <input type="text" name="to" placeholder="Recipient" required>
                <button type="submit">Transfer</button>
            </form>
            
            <hr>
            <a href="/logout">Logout</a>
        </body>
        </html>
    `);
});

// Transfer endpoint
app.post('/transfer', (req, res) => {
    const username = req.cookies.session;
    if (!username || !users[username]) {
        return res.redirect('/?error=session_expired');
    }
    
    const { amount, to } = req.body;
    if (users[username].balance >= amount) {
        users[username].balance -= amount;
        return res.redirect('/dashboard?success=transfer_complete');
    }
    res.redirect('/dashboard?error=insufficient_funds');
});

// Homepage with error handling
app.get('/', (req, res) => {
    if (req.cookies.session && users[req.cookies.session]) {
        return res.redirect('/dashboard');
    }
    
    const error = req.query.error;
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login</title>
            <meta charset="utf-8">
            <style>
                .error { color: red; }
                .success { color: green; }
            </style>
        </head>
        <body>
            <h1>Bank Login</h1>
            ${error ? `<p class="error">${
                error === 'session_expired' ? 'Session expired' : 
                'Invalid credentials'
            }</p>` : ''}
            
            <form action="/login" method="POST">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                <button type="submit">Login</button>
            </form>
            
            <p>Demo accounts:</p>
            <ul>
                <li>alice / password123</li>
                <li>bob / securepass</li>
            </ul>
        </body>
        </html>
    `);
});

// Logout with proper cookie clearing
app.get('/logout', (req, res) => {
    res.clearCookie('session', { path: '/' });
    res.redirect('/');
});

app.listen(3000, () => console.log('App running on port 3000'));
```
</details>


### How the App Works

- Users log in with a username and password.
    
- Once logged in, a **session cookie** keeps the user authenticated.
    
- The dashboard allows users to **transfer money** by submitting a form.
    
- The app automatically trusts any incoming requests as long as the session cookie is valid.

### Key Vulnerabilities

- **Only Cookies for Authentication**  
    The app relies entirely on session cookies to identify users — no CSRF tokens, no re-verification.
    
- **Important Action Available**  
    Transferring money is an action that attackers would want to exploit.
    
- **No Secret or Randomized Parameters**  
    The transfer request only needs an amount and a recipient, both of which an attacker can easily guess or control.

### Exploring the bank app

If everything is right we should see a login page like so. I am using docker to run this locally. 

![login page](https://i.ibb.co/xSMK72J9/image.png)

In our app we did have two users and we can try and login as one of them `alice:password123`

We should see this dashboard that displays our balance. 

![dashboard](https://i.ibb.co/GbQrkcw/image.png)

There is also a session cookie that is set. `SameSite="LAX"` in cookies allows the browser to send the cookie with top level navigations from other sites, but only if the request method is safe, such as GET or HEAD not POST. That means that if a user clicks a link from another site to your site, the cookie will be sent, unless the request is not a safe method.
You can read more on it here. [SameSite Cookies explained](https://web.dev/articles/samesite-cookies-explained)

![cookie](https://i.ibb.co/Nb7Wzdd/image.png)


All of this does meet the conditions required for a CSRF. Where the action of transferring funds is of interest to the attacker. The application also uses a session cookie to identify the user that issued the request


### Exploiting CSRF: The Malicious HTML Page

Now that we have our vulnerable banking app set up, we can simulate an attack using a malicious *HTML page*. The page will trick the victim into executing actions on the vulnerable web app without their consent.
In the previous section, we saw that our banking app was vulnerable to CSRF attacks because it relied solely on session cookies to authenticate users, without any form of validation for requests coming from third-party websites. This makes it possible for an attacker to forge requests that the app will treat as legitimate.

<details>
<summary> Click to view full code (malcious.html) </summary>

```html

<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Claim Your Reward!</title>
  </head>
  <body>
    <h1>Congratulations! 🎉</h1>
    <p>Click the button below to claim your $1000 reward!</p>

    <button id="claim-prize-btn">Claim Reward</button>

    <script>
      document
        .getElementById("claim-prize-btn")
        .addEventListener("click", function () {
          const form = document.createElement("form");
          form.method = "POST";
          form.action = "http://localhost:3000/transfer";

          const amountInput = document.createElement("input");
          amountInput.type = "hidden";
          amountInput.name = "amount";
          amountInput.value = "1000";

          const toInput = document.createElement("input");
          toInput.type = "hidden";
          toInput.name = "to";
          toInput.value = "bob";

          form.appendChild(amountInput);
          form.appendChild(toInput);

          document.body.appendChild(form);
          form.submit(); // Only submit when button is clicked
        });
    </script>
  </body>
</html>
```
</details>

In the above example the attacker would trick the victim into clicking a button that initiates a transfer from the victim's account to another account. Let us break it down. 

1. **The Claim Reward Button**

- The page contains a **button** labeled "Claim Reward." This button is the decoy that entices the victim to click it. When clicked, it triggers the CSRF attack by sending a **forged request** to the vulnerable banking app.

2. **Triggering the CSRF Attack**

- The JavaScript code listens for a **click event** on the button. When the button is clicked, it sends a **POST request** to the banking app's `/transfer` endpoint.
    
- **Form Data**: The request contains the data `amount=1000` (to transfer $1000) and `to=bob` (indicating the recipient account, which could be the attacker’s or a target account).

Our malicious page would look something like this. 

![malicious](https://i.ibb.co/mrn2yHHL/image.png)


When we click the claim reward button then the script executes and transfers the money 

![transfersuccess](https://i.ibb.co/pjfpQ66s/image.png)

### Analyzing the Attack with Burp Suite

To better understand the attack under the hood, let us spin up burp suite and walk through each request made by the malicious page. 

![Burpreq](https://i.ibb.co/RkGKPJHg/image.png)

After we click the button this request is made to `/transfer` 

![transfer](https://i.ibb.co/tGcfj8n/image.png)

## Defenses Against CSRF

These days, successfully finding and exploiting CSRF vulnerabilities often involves bypassing anti-CSRF protections implemented by the target website, the victim's browser, or both.  
Modern applications typically use one or more of the following defenses:

- **CSRF Tokens**:  
    A CSRF token is a unique, secret, and unpredictable value generated by the server-side application and shared with the client.  
    When performing a sensitive action, the client must include the correct CSRF token in their request.  
    Because an attacker cannot predict or retrieve this token, it becomes extremely difficult for them to forge a valid request on behalf of the victim.
    
- **SameSite Cookies**:  
    The SameSite attribute is a browser-level security mechanism that controls when cookies are included in cross-site requests.  
    If a website sets its cookies with `SameSite=Lax` or `SameSite=Strict`, the browser will automatically prevent those cookies from being sent along with requests originating from other domains.  
    Since sensitive actions typically require an authenticated session cookie, enforcing SameSite restrictions can block many CSRF attacks before they reach the server.
    
- **Referer-Based Validation**:  
    Some applications defend against CSRF by checking the `Referer` header in incoming requests.  
    By verifying that the request originated from the application's own domain, the server can reject suspicious requests from external sites.  
    However, this method is less reliable than CSRF tokens, as some browsers or privacy tools may strip or modify the `Referer` header.
    

---

> **In Summary**:  
> Strong CSRF defenses focus on verifying that each request truly came from the intended user, either by checking unique tokens, enforcing browser restrictions, or validating request origins.


## Flaws in CSRF token Validation 

To learn about CSRF token validation flaws, we need to go back and learn about CSRF tokens. As we mentioned previously this token is a unique, secret and unpredictable value generated and shared with the  client and is used to validate sensitive actions when a form is submitted. 

### Adding CSRF Protection to our Bank Application

1. We could start by generating a CSRF token during the login process. This token will be unique to each session and will be used to validate requests. Using the `crypto` module.

```js
const crypto = requre('crypto');
```

Then after a succesful login we can generate a token for the user session. 

```js
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users[username];

    if (user && user.password === password) {
        // Generate a CSRF token
        const csrfToken = crypto.randomBytes(24).toString('hex');

        // Set the CSRF token as a cookie
        res.cookie('csrfToken', csrfToken, { 
            httpOnly: true,
            sameSite: 'Lax', // SameSite helps with CSRF prevention
            path: '/'
        });

        // Store the CSRF token in the user's session data
        res.cookie('session', username, { 
            httpOnly: true, 
            sameSite: 'Lax', 
            path: '/' 
        });

        return res.redirect('/dashboard');
    }
    res.status(401).send(`
        Invalid credentials! 
        <a href="/">Try again</a>
    `);
});
```

2. Now we can embed the CSRF token in the sensitive form (the money transfer form) so that each submission includes the correct token. 

```js
// Dashboard page (after login)
app.get('/dashboard', (req, res) => {
    const username = req.cookies.session;
    const csrfToken = req.cookies.csrfToken;

    if (!username || !users[username]) {
        return res.redirect('/?error=session_expired');
    }

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
        </head>
        <body>
            <h1>Welcome, ${username}!</h1>
            <h2>Balance: $${users[username].balance}</h2>
            <form action="/transfer" method="POST">
                <h3>Transfer Money</h3>
                <input type="hidden" name="csrfToken" value="${csrfToken}">
                <input type="number" name="amount" placeholder="Amount" required>
                <input type="text" name="to" placeholder="Recipient" required>
                <button type="submit">Transfer</button>
            </form>
            <hr>
            <a href="/logout">Logout</a>
        </body>
        </html>
    `);
});

```

3. Validate the CSRF token in transfer request

Now when the user submits the transfer form, we need to validate this on the server before processing the transfer. 

```js
app.all('/transfer', (req, res) => {
    const username = req.cookies.session;

    if (!username || !users[username]) {
        return res.redirect('/?error=session_expired');
    }

    if (req.method === 'POST') {
        const csrfTokenCookie = req.cookies.csrfToken;
        const csrfTokenBody = req.body.csrfToken;

        // Check CSRF token validity for POST only
        if (!csrfTokenBody || csrfTokenBody !== csrfTokenCookie) {
            return res.status(403).send("CSRF validation failed.");
        }
    }

    // For both GET and POST, process the request
    const amount = parseInt(req.body.amount || req.query.amount);
    const to = req.body.to || req.query.to;

    if (users[username].balance >= amount) {
        users[username].balance -= amount;
        return res.redirect('/dashboard?success=transfer_complete');
    }
    res.redirect('/dashboard?error=insufficient_funds');
});

```

4. Clearing the token on logout

Finally when the user logs out, we will clear both the session and CSRF token cookies to ensure none is left over. 

```js
// Logout handler
app.get('/logout', (req, res) => {
    res.clearCookie('session', { path: '/' });
    res.clearCookie('csrfToken', { path: '/' });
    res.redirect('/');
});

```

For the full code click below. 

<details>
<Summary> Click </summary>

```js
const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

// Add this middleware to set proper headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    next();
});

const users = {
    'alice': { password: 'password123', balance: 5000 },
    'bob': { password: 'securepass', balance: 2500 }
};

// Login route with CSRF token generation
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    
    if (user && user.password === password) {
        // Generate a CSRF token
        const csrfToken = crypto.randomBytes(24).toString('hex');

        // Set the CSRF token as a cookie
        res.cookie('csrfToken', csrfToken, { 
            httpOnly: true,
            sameSite: 'Lax', // SameSite helps with CSRF prevention
            path: '/'
        });

        // Set session cookie
        res.cookie('session', username, { 
            httpOnly: true, 
            sameSite: 'Lax', 
            path: '/' 
        });

        return res.redirect('/dashboard');
    }
    res.status(401).send(`
        Invalid credentials! 
        <a href="/">Try again</a>
    `);
});

// Dashboard page with CSRF token embedded in the form
app.get('/dashboard', (req, res) => {
    const username = req.cookies.session;
    const csrfToken = req.cookies.csrfToken;

    if (!username || !users[username]) {
        return res.redirect('/?error=session_expired');
    }

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
        </head>
        <body>
            <h1>Welcome, ${username}!</h1>
            <h2>Balance: $${users[username].balance}</h2>
            <form action="/transfer" method="POST">
                <h3>Transfer Money</h3>
                <input type="hidden" name="csrfToken" value="${csrfToken}">
                <input type="number" name="amount" placeholder="Amount" required>
                <input type="text" name="to" placeholder="Recipient" required>
                <button type="submit">Transfer</button>
            </form>
            <hr>
            <a href="/logout">Logout</a>
        </body>
        </html>
    `);
});

app.all('/transfer', (req, res) => {
    const username = req.cookies.session;

    if (!username || !users[username]) {
        return res.redirect('/?error=session_expired');
    }

    if (req.method === 'POST') {
        const csrfTokenCookie = req.cookies.csrfToken;
        const csrfTokenBody = req.body.csrfToken;

        // Check CSRF token validity for POST only
        if (!csrfTokenBody || csrfTokenBody !== csrfTokenCookie) {
            return res.status(403).send("CSRF validation failed.");
        }
    }

    // For both GET and POST, process the request
    const amount = parseInt(req.body.amount || req.query.amount);
    const to = req.body.to || req.query.to;

    if (users[username].balance >= amount) {
        users[username].balance -= amount;
        return res.redirect('/dashboard?success=transfer_complete');
    }
    res.redirect('/dashboard?error=insufficient_funds');
});


// Homepage with login form
app.get('/', (req, res) => {
    if (req.cookies.session && users[req.cookies.session]) {
        return res.redirect('/dashboard');
    }
    
    const error = req.query.error;
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login</title>
            <meta charset="utf-8">
            <style>
                .error { color: red; }
                .success { color: green; }
            </style>
        </head>
        <body>
            <h1>Bank Login</h1>
            ${error ? `<p class="error">${
                error === 'session_expired' ? 'Session expired' : 
                'Invalid credentials'
            }</p>` : ''}
            
            <form action="/login" method="POST">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                <button type="submit">Login</button>
            </form>
             
        </body>
        </html>
    `);
});

// Logout with proper cookie clearing
app.get('/logout', (req, res) => {
    res.clearCookie('session', { path: '/' });
    res.clearCookie('csrfToken', { path: '/' });
    res.redirect('/');
});

app.listen(3000, () => console.log('App running on port 3000'));
```
</details>

### Validation of Tokens Based on Request Methods

Some applications correctly validate the CSRF token when handling `POST` requests, but mistakenly skip validation for `GET` requests. This oversight can leave the application vulnerable if sensitive actions can still be performed via `GET`.

![post](https://i.ibb.co/r2j9YdWF/image.png)

For example we can note that when we send a post request here we get back a `CSRF validation failed`. What happens when we change that to a `GET`?  

![GET](https://i.ibb.co/FbXWM3dm/image.png)


## Mitigating and Preventing CSRF Attacks

Understanding CSRF vulnerabilities is important, but even more critical is knowing how to properly defend against them. Over the years, many effective strategies have been developed to prevent CSRF attacks from succeeding. Some of the most common and effective defenses include:

### Use Anti-CSRF Tokens

Generate a random, unpredictable token for each user session and include it in every state-changing request (like form submissions).  
The server should verify that the received token matches the expected value.  
Since attackers cannot predict the correct token, forged requests will fail.

> 🔥 **Important:** Always validate the token on **every** sensitive request, no matter the HTTP method (POST, GET, PUT, DELETE, etc.).



### Enforce SameSite Cookie Attribute

Set the `SameSite` attribute on cookies to `Strict` or `Lax`.  
This tells the browser not to send cookies with cross-site requests, effectively blocking many CSRF attacks automatically.

`Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict`

> 💡 **Tip:** `SameSite=Lax` is usually a good balance for most apps, but critical apps like banks may prefer `SameSite=Strict`.



### Validate the Origin or Referer Header

Servers can check the `Origin` or `Referer` HTTP header to confirm that a request came from their own domain.

- If the `Origin` header is missing or does not match, reject the request.
    
- Be cautious, because some browsers or network setups might strip these headers.
    
```
if (!req.headers.origin || !req.headers.origin.includes('your-domain.com')) {     return res.status(403).send('Invalid request origin.'); }`
```

### Avoid Sensitive Actions via GET Requests

Sensitive operations (like money transfers, deleting data, changing account settings) should **never** be performed using `GET` requests.

> ✅ Always use `POST`, `PUT`, or `DELETE` for actions that change server state.

GET requests are meant to be safe and idempotent (they should not modify anything).


### Implement Double Submit Cookies (optional)

Another method involves setting a CSRF token both in a cookie and in a request parameter.  
The server then checks that both values match.

This method is weaker than server-side session tokens but is still better than nothing if sessions are stateless.

## Resources

1. [Owasp csrf](https://owasp.org/www-community/attacks/csrf)
2. [Portswigger](https://portswigger.net/web-security/learning-paths/csrf/)
3. [Prevention Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#introduction)

## Comments

{{< chat disqus_thread >}}

---
