import re
import ipaddress
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="centered",
)

# Transparent, rule-based baseline. This is a demo, not a trained ML model
# and not a live threat-intelligence/reputation service.
SCAM_PATTERNS = [
    ("Urgent or threatening language", [
        r"\b(urgent|immediately|act now|final warning|within \d+ hours?|account will be blocked|suspended today|expires today)\b",
        r"\b(తక్షణం|వెంటనే|అత్యవసరం|బ్లాక్ చేయబడుతుంది|నిలిపివేయబడుతుంది)\b",
    ], 2),
    ("Requests for passwords, OTPs, or verification codes", [
        r"\b(otp|one[- ]time password|password|pin number|cvv|verification code|login credentials)\b",
        r"\b(share|send|confirm|verify|provide|enter)\b.{0,35}\b(otp|password|pin|cvv|verification code)\b",
        r"\b(ఓటీపీ|పాస్‌వర్డ్|పిన్)\b",
    ], 4),
    ("Money, fees, or payment pressure", [
        r"\b(pay now|pay a fee|pay (a|the) (registration|processing|advance) fee|processing fee|advance payment|send money|transfer funds|claim your prize|pay to receive|refund pending)\b",
        r"\b(bank account|upi|payment link|gift card|crypto wallet)\b",
        r"\b(డబ్బు చెల్లించండి|ఫీజు చెల్లించండి|బహుమతి)\b",
    ], 2),
    ("Prize or unrealistic reward claims", [
        r"\b(you have won|winner|lottery|free prize|guaranteed job|earn \₹?\s?\d+ per day|risk[- ]free profit)\b",
        r"\b(మీరు గెలుచుకున్నారు|లాటరీ)\b",
    ], 2),
    ("Suspicious job or recruitment language", [
        r"\b(job offer|work from home|no experience required|registration fee|interview fee|instant hiring)\b",
    ], 1),
    ("Impersonation or unusual account verification", [
        r"\b(verify your account|kyc update|bank support|customer care|your account is locked|click to reactivate)\b",
    ], 2),
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"
}
SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".xyz", ".work", ".gq", ".tk"}
URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"']+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>"']*)?)""")

def extract_urls(text):
    found = []
    for raw in URL_RE.findall(text or ""):
        cleaned = raw.rstrip(".,!?;:)]}")
        if cleaned.lower().startswith("www."):
            cleaned = "http://" + cleaned
        elif not re.match(r"(?i)^https?://", cleaned):
            cleaned = "http://" + cleaned
        if cleaned not in found:
            found.append(cleaned)
    return found

def inspect_url(raw_url):
    findings = []
    try:
        parsed = urlparse(raw_url)
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return ["Could not parse this URL; verify it manually."]
        try:
            ipaddress.ip_address(host)
            findings.append("The link uses a raw IP address instead of a typical domain.")
        except ValueError:
            pass
        if host in SHORTENERS:
            findings.append("The link uses a URL-shortening service, which hides the destination.")
        if host.startswith("xn--") or ".xn--" in host:
            findings.append("The domain contains punycode, which can be used in look-alike domains.")
        if host.count(".") >= 4:
            findings.append("The domain has many subdomain levels; verify the registered domain carefully.")
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append("The domain uses a TLD sometimes seen in suspicious links; this alone does not prove fraud.")
        if parsed.scheme != "https":
            findings.append("The link does not use HTTPS. This is not proof of a scam, but avoid entering sensitive data.")
        if "@" in parsed.netloc:
            findings.append("The URL contains an @ symbol in its authority section; inspect the true destination carefully.")
        if not findings:
            findings.append("No obvious URL-pattern warning was found. This does not establish that the link is safe.")
        return findings
    except Exception:
        return ["The URL could not be fully analyzed. Verify it independently."]

def analyze(text):
    normalized = (text or "").lower()
    findings = []
    score = 0
    for title, patterns, points in SCAM_PATTERNS:
        if any(re.search(p, normalized, flags=re.IGNORECASE) for p in patterns):
            findings.append(title)
            score += points

    urls = extract_urls(text)
    for url in urls:
        url_findings = inspect_url(url)
        for finding in url_findings:
            # A "no obvious warning" note is useful but should not raise the score.
            if finding.startswith("No obvious URL-pattern warning"):
                continue
            if finding.startswith("The link does not use HTTPS"):
                score += 1
            else:
                score += 2
            findings.append(f"URL check ({url}): {finding}")

    if not findings:
        findings.append("No configured warning pattern was detected. Scams can still be written convincingly.")
    score = min(score, 10)
    if score >= 7:
        level, color, advice = "High", "🔴", "Do not click links or send money or codes. Verify through an official app, website typed manually, or a known phone number."
    elif score >= 4:
        level, color, advice = "Medium", "🟠", "Pause and verify the sender independently. Do not share OTPs, passwords, or payment details."
    else:
        level, color, advice = "Lower based on these rules", "🟢", "Still be cautious. Check the sender and destination independently before taking action."
    return {"score": score, "level": level, "color": color, "findings": findings, "advice": advice, "urls": urls}

TELUGU = {
    "High": {
        "level": "అధిక ప్రమాద సూచనలు",
        "advice": "లింక్‌పై క్లిక్ చేయవద్దు; డబ్బు లేదా OTPలు పంపవద్దు. అధికారిక యాప్/వెబ్‌సైట్ లేదా మీకు తెలిసిన ఫోన్ నంబర్ ద్వారా స్వతంత్రంగా ధృవీకరించండి."
    },
    "Medium": {
        "level": "మధ్యస్థ ప్రమాద సూచనలు",
        "advice": "ఆగి పంపిన వ్యక్తిని స్వతంత్రంగా ధృవీకరించండి. OTPలు, పాస్‌వర్డ్‌లు లేదా చెల్లింపు వివరాలు పంచుకోవద్దు."
    },
    "Lower based on these rules": {
        "level": "ఈ నియమాల ప్రకారం తక్కువ సూచనలు",
        "advice": "అయినా జాగ్రత్తగా ఉండండి. ఏ చర్య తీసుకునే ముందు పంపిన వ్యక్తి, లింక్‌ను స్వతంత్రంగా తనిఖీ చేయండి."
    }
}

st.markdown("""
<style>
.block-container {max-width: 850px; padding-top: 2rem; padding-bottom: 3rem;}
.hero {padding: 1.25rem; border-radius: 18px; background: linear-gradient(135deg,#10243a,#145a66); color: white;}
.hero h1 {color: white; margin-bottom: .2rem;}
.hero p {color: #d5e8ee; margin-bottom: 0;}
.small-note {font-size: .88rem; color: #6b7280;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="hero"><h1>🛡️ ScamShield AI</h1><p>Your digital safety assistant · Explainable scam-warning demo</p></div>', unsafe_allow_html=True)
st.write("")
language = st.selectbox("Explanation language / వివరణ భాష", ["English", "తెలుగు"])
st.write("Paste a suspicious SMS, job offer, payment request, or URL below.")
sample = st.selectbox(
    "Try a sample",
    [
        "Custom input",
        "Suspicious bank alert",
        "Suspicious job offer",
        "Possible legitimate message",
        "Suspicious shortened link",
    ],
)
samples = {
    "Suspicious bank alert": "URGENT: Your bank account will be blocked today. Verify your account immediately and share your OTP using this link: http://bit.ly/example",
    "Suspicious job offer": "Congratulations! Guaranteed job offer. Pay a registration fee now to secure your work from home position. No experience required.",
    "Possible legitimate message": "Reminder: Your appointment is scheduled for tomorrow at 10 AM. Please contact the clinic using the number you already have if you need to reschedule.",
    "Suspicious shortened link": "Your parcel is on hold. Click immediately to release it: http://tinyurl.com/example",
}
default_text = samples.get(sample, "")
message = st.text_area(
    "Message or URL",
    value=default_text,
    height=170,
    placeholder="Paste text here, including any suspicious URL...",
    help="Demo analysis runs locally in this app. Avoid pasting real private messages or personal information."
)
analyze_button = st.button("🔎 Analyze for warning signs", type="primary", use_container_width=True)

if analyze_button:
    if not message.strip():
        st.warning("Please enter a message or URL first.")
    else:
        result = analyze(message)
        telugu_result = TELUGU[result["level"]]
        display_level = telugu_result["level"] if language == "తెలుగు" else result["level"]
        display_advice = telugu_result["advice"] if language == "తెలుగు" else result["advice"]

        st.divider()
        st.subheader("Analysis result / విశ్లేషణ ఫలితం")
        col1, col2 = st.columns(2)
        col1.metric("Rule-based risk score", f'{result["score"]}/10')
        col2.metric("Risk assessment", display_level)
        st.progress(result["score"] / 10)
        st.markdown("**Warning signs found / కనిపించిన హెచ్చరికలు**")
        for finding in result["findings"]:
            st.write(f"• {finding}")
        st.markdown("**Recommended next step / సూచన**")
        st.info(display_advice)
        if result["urls"]:
            st.markdown("**URLs detected**")
            for url in result["urls"]:
                st.code(url)
        st.caption("Important: This is a transparent rule-based prototype, not a trained AI classifier or live URL reputation service. Scores are heuristic, may be wrong, and must not be treated as proof. A low score does not mean a message is safe.")
else:
    st.info("Tip: choose a sample above and click Analyze to see the demo.")
    st.markdown("### What this demo checks")
    st.write("- Urgency and threats")
    st.write("- Requests for OTPs, passwords, or verification codes")
    st.write("- Payment pressure and unrealistic rewards")
    st.write("- Basic URL patterns such as shorteners, IP-address links, and non-HTTPS links")
    st.caption("A suspicious pattern is a warning sign, not proof of fraud.")
