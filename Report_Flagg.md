### Vulnerabilities
#### A1:2017

#### Injections 
Are An injection is when attacker uses natural application behaviors to inject or sends malicious code or commandsto a system to be interpreted or executed with ill intent. Nearly any source of data can represent a differentinjector vector, including environmental variable, parameter, external and internal web services, or any type ofusers. These attacks include system calls, the use of external programs via shell commands, as well as calls tobackend databases via SQL. The exposure of this threat is highlighted in the following risk chart.When web applications pass information through HTTP request as part of the actual request, the request mustbe carefully scrubbed. Otherwise, the attacker can inject special (meta) characters, malicious commands, orcommand modifiers into the information and the web application will blindly pass these on to the next systemcomponent for execution.Scope of InjectionsEvery web application environment allows the execution of external commands such as system calls, shellcommands, and SQL requests. The susceptibility of an external call to command injection depends on how thecall is made and the specific component that is being called, but almost all external calls can be attacked if theweb application is not properly coded.Injection flaws are very prevalent, especially in legacy code and can be found in SQL, NoSQL, LDAP, OSqueries, XML parsers, SMTP headers, expression languages, and QRM queries. So while prevalent they arealso easily detected and discovered when examining code or using one of the many new tools like scanners andfuzzers. Even though injections can easily be discovered they can do some serious damage including data loss,data corruption, or disclosure of PII data, or even a complete host take over. The financial impact enormous,even unrecoverable.

#### How They Works

Any application can vulnerable to attack if the user input is not sufficiently scrubbed, filtered, or sanitized bythe application. Dynamic queries or non-parameterized calls without contextaware escaping are used directlyin the interpreter. When hostile data is directly used or concatenated into SQL or command the data thencontains both structure and hostile data in the form of dynamic queries, commands, or stored procedures. Source code review is the best method of detecting if applications are vulnerable to injections, closely followedby thorough automated testing of all parameters, headers, URL, cookies, JSON, SOAP, and XML data inputs.Organizations can include static source (SAST) and dynamic application test (DAST) tools into the CI/CDpipeline to identify newly introduced injection flaws prior to production deployment. 

#### Construct and Deliver
Using a 3 step process an injection can be constructed and carried out on any vulnerable system: 
1.  Fingerprinting
1.  Exploitation
1.  Administration

In fingerprinting a process inspecting HTTP headers can reveal what programming language an application iswritten in, what port is being used, what web service engine is being used, all using standard tools like Telnet,openssl, HTTP GET request, Directory Buster, Burp Suite(http://portswigger.net/) being used as a proxy asshown in the image below.   A thorough understanding of how SQL statements are constructed is necessary to exploit SQL injections. Thereare different detection or discovery methods to find vulnerabilities including the use of integers and strings. In order to find the SQL injection, you need to visit the website and try these methods on all parameters for each page. Once you have found the SQL injection point, you can move on to exploit it.The exploitation of SQL injections requires the proper use and understanding of the UNION key word. The UNION key word is use to join two different statements together as one, for example: “SELECT acct_bal, acct_u-limit, acct_l-limit  FROM accounts WHERE acct_num=1 UNION SELECT cust_addr, cust_login, cust_pwd from customers;” The only rule is that the query must contain the same number of returned columns as original query, may have to guess at this, or the database will trigger an error. Different database technologies will require different parameters or methodology. Another key word can be use to know as ORDER BY, ORDER BY is used to instruct the database on how to sort the returned the result set. Administration is a process of accessing the website and executing the code. This includes cracking the password, which is sometime easier than one may think. The use of a simple search engine or application known as John-The-Ripper can be used to return a hash matching the password. Once system access has been obtained, the next step is to determine how to execute OS commands. If for example a website allows a use to upload a file, they can exploit this by uploading a PHP script that then can execute systems commands. Once a file has been stored on the system, we can inspect the source code to see where the image tag is pointing as seen below.

```html
<div class="inner" align="center">   <p>      <img src="admin/uploads/shell.php3" alt="Test shell" /> </p></div>
 ```
 For command injection, if you don't see any changes, you can also try to play with the time taken by the server to answer. For example, you can use the following commands to create a delay in the server's response:
```bash
>>ping -c 4 127.0.0.1 or >> sleep 5
```
If you see a time delay, it's likely that you can inject commands and run arbitrary commands on the remote server. For example, accessinghttp://dvwa/admin/uploads/shell.php3?cmd=uname -awill run the commanduname -aon the operating system and return the current kernel (Linux).This webshell will only have the same privileges as the webserver so you will not be able to execute all commands since the webserver may not have access itself but, always try as mistake are made. 

#### Prevention 
The only sure way to prevent Injection attacks is input validation and parametrized queries including prepared statements. The application code should never use the input directly. The developer must sanitize all input, not only web form inputs such as login forms. They must remove potential malicious code elements such as single quotes. It is also a good idea to turn off the visibility of database errors on your production sites. Database errors can be used with SQL Injection to gain information about your database.The use of positive or "whitelist" server-side input validation is good start but is not a complete defense as many applications require special characters, such as text areas or APIs for mobile applications. It is important to note that SQL structures such as table names, column names, cannot be escaped, and thus user-supplied structure names are dangerous. This is a common issue in report-writing software. The use of the LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection can be a last resort effort.

#### Logging 
is the process of collecting and storing data over a period of time in order to analyze specific trends or record the data-based events/actions of a system, network or IT environment. It enables the tracking of all interactions through which data, files or applications are stored, accessed or modified on a storage device or application.

#### Application monitoring
is a process that ensures that a software application processes and performs in an expected manner and scope. This technique routinely identifies, measures and evaluates the performance of an application and provides the means to isolate and rectify any abnormalities or shortcomings.

#### Insufficient Logging & Monitoring
Most issue with logging and monitoring comes from poor setup and implementation
Basic devices such as web, mail  and database servers have logging enabled but what's needed in most cases
are Application logging itself. With Application logging missing, hackers can attack end users by stealing their data and 
also spread to the network affecting other servers

Logging & Monitoring
  - Source
    - Application Server
    - API Servers
    - Proxy Servers
    - File Servers
    - Network Traffic
  - Scope includes but not limited too
    - Storing logs locally
    - API Crashes Access 
    - Login Attempts and Failures
    - Users Setting up Monitoring without Alerts or timely alert
    - Application Log
    - etc ....

- Where to record event data 
  - When saving to a file system, use separate user data and operation system data
  - Database logs will use different accounts to store their logs
  - Use standard formats to facilitate integration with centralised logging services
- Event data sources
  - Client, Desktop and mobile software
  - Database triggered actions
  - URL redirects and rewrites of error from custom scripts
- Which events to log
  - Log input validation failures 
  - Authentication successes and failures Authorization (access control) failures
  - Application errors and system events
- Event attributes
  - Application Logs Who, what, when and how for every event
  - Date and time.
  - Application Server IP address name and version number
  - Human or computer interaction
  - Description
- Data to exclude
  - Remove Application source code if logged
  - Database connection strings
  - Personally information
  - Access tokens

- What kinds of attacks can be carried out with Insufficient logging and Monitoring
  - Scanning user password using Rainbow tables
  - Gain access to users account
  - Malware going undetected for months
  - DDOS attacks for web server and APIs
  
#### How it Works
Hacker can attack server and user login attempts undetected for days because either no logging is in place or no one is reading the logs.
There are no alerts to warn teams of repeated login attempts 
Application logging should always be included for security events. Application logs are invaluable data for:
  - Identifying security incidents
  - Monitoring policy violations
  - Establishing baselines
  - Assisting non-repudiation controls
  - Providing information about problems and unusual conditions
  - Contributing additional application-specific data for
    incident investigation which is lacking in other log sources
  - Helping defend against vulnerability identification and exploitation through attack detection

#### Scenario
A hacker gain access to a user account and use that account to send message on behalf of the account owner.
If the logs contain personal data or if the log contain access tokens hacker can make request
to application servers on that users behave.


