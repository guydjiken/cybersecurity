
# Triage and Threat Response

## Objective
[Brief Objective]

The Triage and Threat Response Lab project aimed to monitor, investigate, and respond to potential threats to the network using various security tools. This involved working in a 24x7 SOC (Security Operations Center) environment where we triaged alerts and escalated incidents to higher-level analysts when necessary. This hands-on experience was designed to Junior Security Analyst.

## Project Structure
- [Task 1](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Monitor%20and%20Investigate%20Alerts.py): Thepython code provides a logical framework for monitoring alerts and prioritizing them for investigation.
- [Task 2](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Investigate%20Malicious%20IP%20Address.py): It outlines how you would handle specific alerts, such as investigating a suspicious IP address and escalating it if necessary.
- [Task 3](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Respond%20to%20Compromised%20Hosts%20and%20Malicious%20Processes.py): The python code shows how incident response tasks like isolating compromised hosts and blocking malicious processes would be handled.
- [Task 4](https://github.com/guydjiken/guydjiken.github.io/blob/main/cyber/Generate%20Incident%20Report.py): This part focuses on the documentation and report generation, crucial for any SOC role.

### Task 1: Responsabilities and Technical Skills

##### Responsabilities
- Monitoring security event logs and alerts using SIEM and EDR tools.
- Investigating suspicious activity and conducting basic forensics analysis.
- Configuring and managing Intrusion Detection Systems (IDS) and signature development.
- Escalating significant security incidents to higher-tier analysts.

#### Technical Skills
- Basic understanding of OSI/TCP-IP models.
- Hands-on experience with operating systems (Windows, Linux), programming (Python, Playbook) and networking concepts.
- Use of open-source tools and threat intelligence to identify suspicious behavior.

#### Learning Resources
- Studied for **Google Cybersecurity Professional** certification, focusing on deeper investigations, analysis and remediation.
- Followed cybersecurity news and threat intelligence via **CISA** and **Feedly** to stay updated on new tactics, techniques, and procedures (TTPs).

### Task 2: Monitoring and Investigation

##### Morning Review
- Checking tickets and new alerts generated overnight.

#### Tools Used
- **SIEM** Systems: Analyzing log data and prioritizing alerts based on criticality (Low, Medium, High, Critical).
- **IDS/IPS**: Investigating alerts related to potential intrusions.
- **Open-source Intelligence Tools**: Gathering additional information on IP addresses or domains to validate alerts.

#### Example Alert
- Malicious IP Detected: 221.181.185.159.
- Investigated the IP address using an **IP scanner**, verifying it was linked to a known attacker.
- **Escalation**: Event escalated to IT supervisor for further analysis and action.

### Task 3: Incident Response

##### Immediate Action after Identifyimg the Maliciouis IP address
- **Block** the IP on the firewall.
- Analyze potential damage done and whether data was exfiltrated

#### message from the Attacker
- After blocking the IP, the attacker left a message: **THM{UNTIL-WE-AGAIN}**.

#### Remediation Steps
- Isolated compromised hosts.
- Terminated malicious processes.
- Cleared remnants of the attack from the environment.
- Documented the event and lessons learned for future cases.

### Task 4: Final Reporting and Documentation

#### Investigation alert/incident
###### FOR each investigated alert or incident:
- IF (incident was escalated):
        CREATE detailed report:
            - List all actions taken (Blocking IP, isolating hosts, terminating processes)
            - Include evidence from logs, screenshots, and tools used
            - Summarize attacker behavior (IP address, tactics, message)
            - Provide recommendations for future prevention
- ELSE:
        LOG findings in daily report:
            - List low and medium-priority alerts investigated
            - Document false positives and resolved alerts

- SUBMIT final report to SOC manager for review

## Skills/Tools Demonstrated
- **SIEM**: Efficient use of SIEM for alert triage
- **Firewall Management**: Blocking malicious IP addresses and configuring firewall rules.
- **Forensics**: Basic forensics skills to analyze and identify the scope of an attack.
- **Communication**: Clear escalation process to senior analysts when necessary.


## Conclusion

This project highlights my ability to effectively triage, investigate, and respond to cybersecurity threats in a SOC environment. Through hands-on practice with monitoring tools and alert prioritization, I gained a solid foundation for further advancing in the field of cybersecurity. This project showcases my readiness for a more advanced role, building on my experience with real-world scenarios.