import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email configuration
sender_email = "you@example.com"
receiver_email = "recipient@example.com"
subject = "Test Email from Python"
smtp_server = "smtp.example.com"
smtp_port = 587  # Use 465 for SSL
smtp_user = "you@example.com"
smtp_password = "your_password"

# Create the email
msg = MIMEMultipart()
msg["From"] = sender_email
msg["To"] = receiver_email
msg["Subject"] = subject

# Email body
body = "Hello, this is a test email sent using Python's email package."
msg.attach(MIMEText(body, "plain"))

try:
    # Connect to SMTP server
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()  # Secure connection
    server.login(smtp_user, smtp_password)
    server.send_message(msg)
    print("✅ Email sent successfully!")
except Exception as e:
    print(f"❌ Failed to send email: {e}")
finally:
    server.quit()
