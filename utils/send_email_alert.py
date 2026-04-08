import smtplib
from email.mime.text import MIMEText

def send_email_alert(ip, decision, threat_score, features):
    try:
        # ✅ HARD CODE (PUT YOUR REAL EMAIL HERE)
        sender = "hara33629@gmail.com"
        password = "smvzvsikecvqsmvu"
        receiver = "haritha022006@gmail.com"

        subject = f"🚨 DOS Alert - {decision}"

        html_body = f"""
        <h2>🚨 DOS Alert</h2>
        <p><b>IP:</b> {ip}</p>
        <p><b>Decision:</b> {decision}</p>
        <p><b>Threat Score:</b> {threat_score}</p>
        """

        msg = MIMEText(html_body, "html")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = receiver

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()

        print("🔐 Logging into email...")
        server.login(sender, password)

        print("📤 Sending email...")
        server.sendmail(sender, receiver, msg.as_string())

        server.quit()
        print("✅ Email sent successfully!")

    except Exception as e:
        print("❌ Email Error:", str(e))
