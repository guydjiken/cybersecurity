# Phishing Incident Response Using Playbooks

## Objective
[Brief Objective]

This project demonstrates the investigation and resolution of a phishing incident involving a malicious file hash. It showcases my ability to follow a structured incident response process using a phishing playbook and flowchart to investigate and resolve security alerts in a SOC environment.

## Scenario
As a level-one Security Operations Center (SOC) analyst, I responded to a phishing alert that involved a malicious file downloaded via an email attachment. The file’s SHA256 hash was previously verified as malicious. Using the organization's phishing playbook, I investigated and documented the incident in an alert ticket, following the prescribed steps to mitigate the threat.

## Project Structure
- [Task 1](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Review%20Phishing.py): This script simulates choosing the appropriate response based on the alert's type and severity.
- [Task 2](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Investigation%20Phishing.py): This script simulates investigating an alert by evaluating the email sender details, message body, and file hash.
- [Task 3](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Escalation%20phishing.py): This script simulates deciding whether to escalate or close the alert based on the investigation results.
- [Task 4](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Report%20Phishing.py): This part provided detailed documentation and report the incident resolution.

### Task 1: Accessing and Reviewing the Phishing Playbook

#### Objective
- Use the phishing playbook to understand the structured steps necessary to respond to phishing incidents.

#### Action
- Follow the flowchart and written instructions provided in the playbook to investigate the phishing alert, from alert review to resolution.

### Task 2: Investigating the Phishing Alert

#### Evaluated alert details
- Alert severity (Medium or High, determining escalation).
- Examined the email sender details for inconsistencies.
- Analyzed the message body for typical phishing characteristics (e.g., grammatical errors).
- Investigated attached files and links, focusing on the confirmed malicious file hash.

#### Recorded findings in an incident handler's journal and gathered details about
- Who caused the incident.
- What happened.
- When and where the incident took place.
- Why the incident occurred.

### Task 3: Escalating or Closing the Alert

#### Decision
- Chose to escalate the alert based on the malicious file hash that had been verified and other indicators of compromise within the email.

#### Update Alert Ticket
- updated the ticket status to "Escalated" 
- Added comments summarizing my findings, including:
###### The alert severity level.
###### The confirmed malicious file.
###### The email sender inconsistencies and message body anomalies.

### Task 4: Final Report and Ticket Closure

#### Documentation
- After investigating and escalating the alert, documented the incident fully in the ticket system.
- Provided a summary.
- Detailed the steps taken to mitigate the threat.

## Skills/Tools Demonstrated
- **Phishing Playbook**: Followed structured procedures using the organization's phishing playbook and flowchart to respond to incidents.
- **SIEM**: Reviewed and triaged phishing alert details using event logs and email analysis.
- **Incident Response**: Escalated security alerts and provided actionable reports on phishing incidents.
- **Forensic Analysis**: Investigated email attachments, verified malicious file hashes, and reviewed email content for inconsistencies.
- **Documentation**: Updated and maintained accurate records in the alert ticketing system.

## [Playbook](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Playbook.yml)
- **Steps**: The playbook is broken down into sequential steps, each representing a key part of the incident response process.
- **Action**: Each step contains a set of actions that the SOC analyst or incident responder should take.
- **Decisions**: After each step, decisions guide the workflow to the next step based on the outcome of the investigation.
- **Conditions**: Conditions check the results of each step, such as whether a malicious file hash was detected or if suspicious sender details were found. Based on these conditions, the playbook either escalates the alert or closes it.

## Conclusion

This project highlights my ability to follow structured processes to investigate phishing incidents in a SOC environment. I successfully mitigated the phishing threat by leveraging the phishing playbook and best practices for incident response. My investigation led to an escalation of the alert to higher-tier analysts for further action.
