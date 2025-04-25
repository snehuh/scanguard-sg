# ScanGuard SG

🛡️ A hyper-secure, hyper-convenient QR link safety checker for Singaporean users. 

## 🔍 Problem
Singaporeans are constantly exposed to phishing links via QR codes in public spaces, WhatsApp, and fake promotions. Most people scan without thinking — and there's no easy, local, secure way to check the safety of a QR code.

## 🎯 Vision
Create a web-based Progressive Web App (PWA) that lets users:
- Instantly scan a QR code using their phone camera
- Check if the underlying URL is safe, suspicious, or malicious
- Understand **why** it's risky — not just block it
- All without installing any app

## ✅ Features (Planned)
- QR code scanning in-browser (via HTML5)
- ML-based phishing URL detector
- Singapore-specific scam keyword detection
- Simple result UI (✅/⚠️/❌)
- Lightweight Telegram bot companion (optional)
- No-install, mobile-first experience (PWA)

## 🔒 Security Priorities
- Visual branding to prevent QR code swap attacks
- Short URL (`https://scanguard.sg`) always shown alongside QR
- Transparent predictions with reason explanations

## 🛠️ Tech Stack (Planned)
- Frontend: HTML, JS (`html5-qrcode`)
- Backend: Python (Flask)
- ML: scikit-learn (Naive Bayes or RandomForest)
- Hosting: GitHub Pages (frontend), Railway/Fly.io (backend)

## 📌 Status
**Planning & scoping phase**. Code coming soon!

---

👩‍💻 Built by [@snehuh](https://github.com/snehuh)
