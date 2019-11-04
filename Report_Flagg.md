### A10:2017
#### Definition / Description
Insufficient Logging & Monitoring
- The source, scope, and severity of Insufficient
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

- Where to record event data  
- Event data sources
- Which events to log
- Event attributes
- Data to exclude

- What kinds of attacks can be carried out with Insufficient logging and Monitoring
  - Scanning user password using Rainbow tables
  - Gain access to users account
  - Malware going undetected for months
  - DDOS attacks for web server and APIs
 
#### How it Works
Hacker can attack server and user login attemps undetected for days because either no logging is in place or no one is reading the logs. There are no alerts to warn teams of repeated login attemps 
Application logging should be always be included for security events. Application logs are invaluable data for:

  - Identifying security incidents
  - Monitoring policy violations
  - Establishing baselines
  - Assisting non-repudiation controls
  - Providing information about problems and unusual conditions
  - Contributing additional application-specific data for
    incident investigation which is lacking in other log sources
  - Helping defend against vulnerability identification and       exploitation through attack detection

#### Scenario
A hacker gain access to a user account and use that account to send message on behalf of the account owner.