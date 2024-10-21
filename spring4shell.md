# Malware Attack Leading to NBN Outage

## Objective
[Brief Objective]

The goal of this project is to simulate the role of an Information Security Analyst in the Security Operations Centre (SOC) by managing and responding to a malware attack. The tasks involve triaging the threat, identifying affected infrastructure, and notifying the correct teams for incident response. The project progresses with analyzing firewall logs to understand how the malware spreads and crafting a firewall rule using Python to stop further attacks. Finally, the project concludes with documenting a postmortem report to provide insights and lessons learned from the incident for future reference and audit purposes.

## Scenario: Spring4Shell Malware Attack Simulation
You are an Information Security Analyst working in the Security Operations Centre (SOC) for a large enterprise, Telstra, that provides critical communication services. One of your daily responsibilities is to monitor alerts and respond to incidents that could affect the infrastructure. Today, you receive an urgent alert about an ongoing malware attack exploiting the Spring4Shell vulnerability.

## Project Structure
- [Task 1](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Review%20Phishing.py): This task allows to learn how to quickly and effectively respond to an ongoing malware attack, minimizing impact.
- [Task 2](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Investigation%20Phishing.py): This script conducted in-depth analysis of the malware's behavior to understand its scope and origins.
- [Task 3](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Escalation%20phishing.py): This script implemented technical solutions to mitigate and block the malware from further exploiting vulnerabilities.
- [Task 4](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Report%20Phishing.py): This part presented a detailed postmortem analysis, identifying the root cause and outlining steps for future prevention.

### Task 1: Responding to a Malware Attack

#### Objective
##### Triage the Malware Threat
- Analyze the incoming alert in the Security Operations Centre (SOC) to assess its severity and impact on the organization’s infrastructure.
- Identify which key infrastructure is affected by the malware attack using the provided firewall logs and infrastructure list.
##### Determine Priority and Notify the Appropriate Team
- Based on the criticality of the infrastructure, decide which team should be notified according to the severity of the attack (Networks Team, Mobile Team, nbn Team).
- Communicate the severity and details of the attack clearly to ensure the correct incident response is initiated.
##### Incident Communication
- Draft a concise and contextual email to the appropriate team, providing them with the necessary details (such as the affected infrastructure and timestamp) to begin mitigation efforts.
#### Actions
##### Review Firewall Logs and Infrastructure List [Log_File](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Task_1_2-Firewall_Infrastructure_List.xlsx)
- Use firewall logs to understand the behavior of the malware and identify which services are compromised.
- Refer to the list of infrastructure provided to understand which services need to remain online and uninterrupted.
##### Assess the Severity of the Attack
- Analyze the logs to determine the scope of the attack. Is it targeting high-priority infrastructure (e.g., customer-facing services) or low-priority systems?.
- Based on the findings, assess the severity to decide whether immediate mitigation is required.
##### Identify Affected Infrastructure
- Cross-reference the log data with the provided infrastructure list to determine which systems or services are affected and need immediate attention.
- Prioritize based on critical infrastructure (e.g., systems running the Spring Framework).
##### Draft Email to Notify the Correct Team [Draft1](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/T1_Email_Template.docx)
- Write an email including the following details:
 ###### Timestamp of when the attack occurred.
  ###### Affected infrastructure and its criticality to business operations.
###### The nature of the attack based on your triage.
###### Request for the incident response team to initiate mitigation.
###### Ensure the message is concise and easily understandable.[T1-Model](https://drive.google.com/drive/folders/1TnQOnsMr9GXWdRxU_Js4u2uox5HTLPPQ)
#### Tools
- Email Communication Platform (Outlook, Gmail): Send an email to the appropriate team and include technical details to help them initiate incident response quickly.
- Firewall Logs: Investigate which IP addresses, ports, or services are being targeted by the malware.
- Network Monitoring Tools & SIEM (Splunk, Wireshark): Analyze logs from firewalls and other security devices.
-  Generative AI(Lakera Guard, ChatGPT): provide a privacy guard that protects you against sharing sensitive information into your conversations with ChatGPT.

### Task 2: Analyzing the Attack

#### Objective
##### Analyze Firewall Logs for Malicious Patterns
- Examine the firewall logs to identify specific patterns of network requests related to the Spring4Shell attack.
##### Communicate Findings to the Network Team
- Summarize the identified patterns and characteristics to assist the network team in creating an effective firewall rule to block the attack.

#### Actions
##### Review and Filter Firewall Logs [Log_File](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Task_1_2-Firewall_Infrastructure_List.xlsx)
- Focus on identifying unusual HTTP request methods, headers, or payloads associated with the attack.
##### Draft Email to Notify the Correct Team [T2-Model](https://drive.google.com/drive/folders/1TnQOnsMr9GXWdRxU_Js4u2uox5HTLPPQ)
- Clearly outline the malicious patterns found (e.g., specific HTTP methods or headers) and suggest actionable next steps for the network team.
#### Tools
- Firewall Log Analyzer or SIEM (Splunk): Analyze the firewall logs to detect suspicious activity.
- Email Platform (Outlook): Draft and send a concise email with the findings and mitigation recommendations to the network team.

### Task 3: Technical Mitigation of the Malware Attack

#### Objective
##### Develop a Firewall Rule in Python
- Create a Python-based firewall rule to block malicious traffic identified from the earlier analysis of network requests.
##### Test the Firewall Rule for Effectiveness
- Requirement: [Read_Me](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Introduction-ReadMe.txt),[Firewall_server](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Firewall_Server-Handler.txt), [Test_request](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Test_Requester.txt)
- Simulate the attack using test requests and verify that the firewall successfully blocks the malicious traffic.

#### Actions
##### Write the Python Firewall Rule [Draft_code](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Report%20Phishing.py)
- Implement a Python script in [firewall_server.py]() to filter incoming HTTP requests based on patterns (e.g., specific HTTP headers or payloads) identified during the attack analysis.
##### Test the Firewall Rule with Simulated Traffic [Test_requests](https://drive.google.com/drive/folders/1TnQOnsMr9GXWdRxU_Js4u2uox5HTLPPQ)
- Use the [test_requests.py](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/test_requests.py) script to send test traffic to the server and confirm that the malicious requests are correctly blocked by the firewall rule.
#### Tools
- Python (for writing the firewall rule): Use Python to write and execute the firewall rule that filters out malicious traffic based on specific patterns.
- Test Script (test_requests.py): Use the provided test script to simulate network requests and validate the effectiveness of the firewall rule.

### Task 4: Incident Postmortem

#### Objective
##### Develop a Firewall Rule in Python
- Create a Python-based firewall rule to block malicious traffic identified from the earlier analysis of network requests.
##### Test the Firewall Rule for Effectiveness
- Simulate the attack using test requests and verify that the firewall successfully blocks the malicious traffic.

#### Actions
##### Create a Detailed Incident Timeline [T4-Model](https://drive.google.com/drive/folders/1TnQOnsMr9GXWdRxU_Js4u2uox5HTLPPQ)
- Note the timestamp of the attack’s start, detection, response actions, and final resolution (e.g., 2 hours after the firewall rule was implemented).
##### Perform a Root Cause Analysis [Template](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Report%20Phishing.py)
- Analyze logs and actions taken to identify the primary vulnerability (Spring4Shell) exploited and summarize the sequence of events leading to the attack.
#### Tools
- Incident Response Log (SIEM): Use tools like Splunk or a built-in log analyzer to review logs and compile the incident timeline.
- Documentation Tool (Confluence): Write and organize the postmortem report for record-keeping and team education.

## Conclusion

This project simulates a real-world incident involving a malware attack on critical infrastructure. You, as the SOC analyst, efficiently triaged the alert, coordinated with the Network Team to mitigate the attack using Python firewall rules, and completed the task by documenting the entire incident in a postmortem. This exercise strengthens your ability to respond to and analyze cyber incidents in a structured and timely manner.