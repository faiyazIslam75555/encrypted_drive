from flask import Flask, render_template, request, jsonify, session
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Change this to a strong random key

# ─── CONFIG ────────────────────────────────────────────────────────────────────
SENDER_EMAIL    = "aunondas@gmail.com"       # Your Gmail address
SENDER_PASSWORD = "akkd piaz mgbl dzxf"    # Gmail App Password (NOT your login password)
OTP_EXPIRY_SEC  = 120                          # OTP valid for 2 minutes
# ───────────────────────────────────────────────────────────────────────────────

def generate_otp(length=6):
    return str(random.randint(10**(length-1), 10**length - 1))

def send_otp_email(recipient_email, otp):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your OTP Code"
    msg["From"]    = SENDER_EMAIL
    msg["To"]      = recipient_email

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:0;">
      <div style="max-width:480px;margin:40px auto;background:#fff;border-radius:12px;
                  box-shadow:0 4px 20px rgba(0,0,0,.08);overflow:hidden;">
        <div style="background:linear-gradient(135deg,#667eea,#764ba2);padding:32px;text-align:center;">
          <h1 style="color:#fff;margin:0;font-size:24px;">OTP Verification</h1>
        </div>
        <div style="padding:32px;text-align:center;">
          <p style="color:#555;font-size:16px;">Use the code below to verify your identity:</p>
          <div style="background:#f0f0ff;border:2px dashed #667eea;border-radius:8px;
                      padding:20px;margin:20px 0;letter-spacing:12px;
                      font-size:36px;font-weight:bold;color:#667eea;">{otp}</div>
          <p style="color:#888;font-size:13px;">This OTP expires in <b>2 minutes</b>.<br>
             Do not share it with anyone.</p>
        </div>
        <div style="background:#f9f9f9;padding:16px;text-align:center;">
          <p style="color:#bbb;font-size:12px;margin:0;">Sent automatically — please do not reply.</p>
        </div>
      </div>
    </body></html>
    """
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())

# ─── ROUTES ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/send-otp", methods=["POST"])
def send_otp():
    data  = request.get_json()
    email = data.get("email", "").strip()

    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Invalid email address."})

    otp = generate_otp()
    session["otp"]       = otp
    session["otp_email"] = email
    session["otp_time"]  = time.time()

    try:
        send_otp_email(email, otp)
        return jsonify({"success": True,  "message": f"OTP sent to {email}"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to send email: {str(e)}"})

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data          = request.get_json()
    entered_otp   = data.get("otp", "").strip()
    stored_otp    = session.get("otp")
    stored_time   = session.get("otp_time", 0)

    if not stored_otp:
        return jsonify({"success": False, "message": "No OTP found. Please request a new one."})

    if time.time() - stored_time > OTP_EXPIRY_SEC:
        session.pop("otp", None)
        return jsonify({"success": False, "message": "OTP has expired. Please request a new one."})

    if entered_otp == stored_otp:
        session.pop("otp", None)
        return jsonify({"success": True,  "message": "OTP verified successfully! ✅"})

    return jsonify({"success": False, "message": "Incorrect OTP. Please try again."})

if __name__ == "__main__":
    app.run(debug=True)
