import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import SENDER_EMAIL, SENDER_PASSWORD

def send_otp_email(recipient_email: str, otp: str):
    """Sends a professional HTML OTP email using Gmail SMTP."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Neural Drive Security Code"
    msg["From"]    = f"Neural Drive <{SENDER_EMAIL}>"
    msg["To"]      = recipient_email

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#0f172a;margin:0;padding:0;color:#fff;">
      <div style="max-width:480px;margin:40px auto;background:#1e293b;border-radius:16px;
                  border:1px solid #334155;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,0.5);">
        <div style="background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:32px;text-align:center;">
          <h1 style="color:#fff;margin:0;font-size:24px;letter-spacing:1px;">Security Verification</h1>
        </div>
        <div style="padding:40px;text-align:center;">
          <p style="color:#94a3b8;font-size:16px;margin-bottom:24px;">Use the following code to access your Neural Drive:</p>
          <div style="background:#0f172a;border:2px solid #6366f1;border-radius:12px;
                      padding:24px;margin:20px 0;letter-spacing:10px;
                      font-size:32px;font-weight:bold;color:#6366f1;display:inline-block;">{otp}</div>
          <p style="color:#64748b;font-size:13px;margin-top:24px;">This code expires in 2 minutes.<br>
             If you didn't request this, please ignore this email.</p>
        </div>
        <div style="background:#0f172a;padding:16px;text-align:center;border-top:1px solid #334155;">
          <p style="color:#475569;font-size:11px;margin:0;">&copy; 2026 Neural Drive — Secure Encrypted Cloud</p>
        </div>
      </div>
    </body></html>
    """
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        print(f"✅ [MAIL SUCCESS] OTP sent to {recipient_email}")
        return True
    except smtplib.SMTPAuthenticationError:
        print("❌ [MAIL ERROR] Gmail Authentication Failed! Check your App Password in config.py.")
        return False
    except Exception as e:
        print(f"❌ [MAIL ERROR] {e}")
        return False
