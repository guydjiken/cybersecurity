# Security Incident Investigation Using Chronicle SIEM

## Objective
[Scenario - Brief Objective](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Scenario.md)

In this project, you will utilize Google Security Operations (Chronicle), a cloud-native SIEM tool, to investigate a phishing-related security incident and answer specific investigative questions. Through this activity, you'll deepen your understanding of how SIEM tools like Chronicle collect, analyze, and report data from multiple sources. As a security analyst, you'll leverage these tools to identify, investigate, and respond to security threats effectively.

## Project Structure
- [Task 1](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Monitor%20and%20Investigate%20Alerts.py): This part investigates the phishing email received by the employee.
- [Task 2](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Investigate%20Malicious%20IP%20Address.py): Determining the scope of exposure across the organization.
- [Task 3](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Respond%20to%20Compromised%20Hosts%20and%20Malicious%20Processes.py): Understanding the potential threat posed by the suspicious domain.
- [Task 4](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Generate%20Incident%20Report.py): This part focuses on containing the threat and implementing remediation actions.

### Task 1: Review and Analyze the Initial Alert

##### Responsabilities
- Review the alert to understand the nature of the phishing email.
- Identify and verify the suspicious domain **signin.office365x24.com**.
- Document initial findings, including email details, sender information, and any related Indicators Of Compromise (**IOCs**).

#### Technical Skills
- Familiarity with email security tools like **Microsoft Defender for Office 365**.
- Expertise in analyzing email headers, metadata, and body content with **G Suite Toolbox Message Header**.
- Experience using threat intelligence platforms like **VirusTotal**, **WHOIS**, and **Google Safe Browsing** to verify suspicious domains.
- Ability to leverage security information and event management (SIEM) tools like Chronicle SIEM to track domain-related activities.

#### Learning Resources
- Studied for **Google Cybersecurity Professional** certification, focusing on deeper investigations, analysis and remediation.
- Learn about SIEM concepts, tools, and practical applications for threat detection.
- Followed tutorial WHOIS Domain Lookup and VirusTotal for analyzing files and domains for viruses and malicious activity.
- Google chronicle Documentation - Official Google Chronicle documentation and learning resources.

### Task 2: Investigate the Domain in Chronicle SIEM

##### Responsabilities
- Perform a domain search in Chronicle SIEM for **signin.office365x24.com**.
- Analyze historical data to see if any other employees received emails containing the domain.
- Identify any network activity related to this domain (example: attempted visits or DNS queries).
- Document any identified users or devices that interacted with the domain.

#### Technical Skills
- Knowledge of query languages to filter and investigate logs.
- Ability to analyze historical log data for patterns in emails, IP addresses, and domains across users.
- Experience with tools like Wireshark and Suricata for inspecting network traffic.
- Experience with Endpoint Detection and Response (**EDR**) solutions to track compromised devices interacting with the domain.

#### Learning Resources
- Studied for **Google Cybersecurity Professional** certification, focusing on deeper investigations and analysis with Google Chronicle Training.
- ELK Stack Tutorial – Learn how to search and analyze historical data using Elastic's ELK stack.
- Network Traffic Analysis Using Wireshark – Udemy Course
- Tool: OSSEC – Open-source tool for host-based intrusion detection and correlating user activity with network interactions.

### Task 3: Assess Threat Intelligence and Risk

##### Responsabilities
- Investigate threat intelligence related to **signin.office365x24.com** in Chronicle.
- Assess the risk level based on known attack patterns, domain reputation, and associated IP addresses.
- Correlate the phishing domain with known phishing campaigns or malware.
- Update the incident report with risk assessment and relevant intelligence.

#### Technical Skills
- Risk assessment and analysis based on domain reputation and known phishing or malware patterns, using tools like MITRE ATT&CK.
- Ability to correlate phishing domains with known campaigns, using threat intelligence feeds and phishing databases to identify trends and campaign connections.
- Ability to compile comprehensive incident reports including threat intelligence findings, risk assessments, and recommended remediation actions.

#### Learning Resources
- MITRE ATT&CK Framework – A comprehensive resource for understanding attack patterns, techniques, and tactics to aid in risk assessment.
- Tool: TheHive Project – An open-source incident response platform that helps manage and document incident response workflows.

### Task 4: Mitigate the Threat and Communicate Findings

##### Responsabilities
- Notify affected employees and security teams of the identified threat.
- Implement measures to block access to the phishing domain across the network (using update firewall and DNS rules).
- Provide recommendations for improving email security (example: enhance phishing detection, conduct awareness training).
- Update the incident handler’s journal with the full investigation process, actions taken, and lessons learned.

#### Technical Skills
- Firewall and DNS configuration skills, allowing you to block malicious domains through firewall rules, DNS blacklisting, and other network security measures.
- Incident documentation and report writing, ensuring detailed and accurate logging of all investigation steps, actions taken, and post-incident analysis to improve future responses.
- Proficiency in incident communication and reporting, ensuring that affected employees and security teams are notified promptly and clearly about security threats, using established protocols.

#### Learning Resources
- Email Security: Protecting Against Phishing and Spoofing – Coursera course covering email security protocols, phishing detection enhancements, and security awareness training.
- Effective Cybersecurity Communication Course on LinkedIn. 

## Conclusion

In this project, we utilized Google Security Operations (Chronicle) to investigate and mitigate a phishing-related security incident.
By leveraging Chronicle's cloud-native SIEM capabilities, we successfully identified the malicious domain and assessed its potential impact on your organization. This experience reinforced your skills in threat intelligence, risk assessment, and incident response.
Overall, the project provided valuable insights into how SIEM tools are used by security analysts to detect and respond to evolving cyber threats effectively.