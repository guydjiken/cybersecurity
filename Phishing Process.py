# Step 1: Review the playbook
def review_playbook(alert_type, alert_severity):
    if alert_type == "phishing" and alert_severity in ["Medium", "High"]:
        return "Follow phishing playbook: Investigate sender details, analyze message body, check attachments."
    else:
        return "Low severity: Monitor alert. No immediate action required."

# Step 2: Investigate the phishing email
def investigate_email(email_data):
    if "fake" in email_data["sender"] or "fake" in email_data["sender_name"].lower():
        print("Suspicious sender detected.")
    if "urgent" in email_data["message_body"].lower():
        print("Phishing language detected in message body.")
    if email_data["attachment_hash"] == malicious_hash:
        print("Malicious file hash detected.")
    return "Investigation complete."

# Step 3: Decide to escalate or close the alert
def escalate_or_close(findings):
    if findings["suspicious_sender"] or findings["malicious_attachment"]:
        return "Escalate the alert to Tier 2."
    else:
        return "Close the alert as non-malicious."

# Step 4: Update the ticket with final status
def update_ticket(ticket, decision, comments):
    ticket["status"] = "Escalated" if "Escalate" in decision else "Closed"
    ticket["comments"] = comments
    return ticket

# Example usage
alert_type = "phishing"
alert_severity = "High"
email_data = {
    "sender": "noreply@fakebank.com",
    "sender_name": "Fake Bank",
    "message_body": "Urgent! Please download the attached file.",
    "attachment_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
malicious_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Step 1: Review the playbook
playbook_instructions = review_playbook(alert_type, alert_severity)
print(playbook_instructions)

# Step 2: Investigate the email
investigation_findings = {
    "suspicious_sender": True,
    "phishing_language": True,
    "malicious_attachment": True
}
investigate_email(email_data)

# Step 3: Escalate or close the alert
decision = escalate_or_close(investigation_findings)
print(f"Decision: {decision}")

# Step 4: Update the ticket
alert_ticket = {"ticket_id": 101, "status": "Investigating", "comments": ""}
final_comments = "Phishing alert verified. Malicious file and suspicious email sender."
updated_ticket = update_ticket(alert_ticket, decision, final_comments)
print(f"Updated Ticket: {updated_ticket}")
