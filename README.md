# ScamShield AI

A beginner-friendly digital safety demo for the VORTEX 2K26 hackathon.

## Current scope

- Paste a message, job offer, payment request, or URL.
- Explainable rule-based warning checks.
- Basic URL-pattern checks.
- English and Telugu next-step guidance.
- Built-in sample inputs for a quick demo.

**Important:** This MVP is a rule-based prototype. It is not a trained AI model, does not query live threat intelligence, and cannot prove a message is safe or fraudulent. Risk scores are heuristic.

## Run locally

1. Install Python 3.10 or newer from https://www.python.org/downloads/
2. Extract this project folder.
3. Open a terminal in the folder.
4. Create a virtual environment (recommended):

   Windows:
   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   ```

   macOS/Linux:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

5. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

6. Start the app:
   ```bash
   python -m streamlit run app.py
   ```

7. Streamlit will show a local URL, usually http://localhost:8501. Open it in your browser.

## Quick test cases

1. Select **Suspicious bank alert** and analyze. Expect urgency, account verification, OTP, and URL warning indicators.
2. Select **Suspicious job offer** and analyze. Expect job/fee/reward warning indicators.
3. Select **Possible legitimate message** and analyze. Expect few or no configured warning patterns.
4. Select **Suspicious shortened link** and analyze. Expect a shortener warning.
5. Paste `https://example.com` and analyze. The app should not claim the site is safe; it should state no obvious URL-pattern warning was found.
6. Switch to Telugu and verify the risk label and recommended action change language.

These are smoke tests, not a scientific accuracy evaluation. Record actual outcomes and limitations in the presentation.

## GitHub upload

1. Sign in at https://github.com/
2. Create a **public** repository named `scamshield-ai` (public is convenient for Streamlit deployment).
3. Add `app.py`, `requirements.txt`, and `README.md` to the repository. You can upload them in the browser, or use Git:
   ```bash
   git init
   git add app.py requirements.txt README.md
   git commit -m "Build ScamShield AI MVP"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/scamshield-ai.git
   git push -u origin main
   ```
   Replace `YOUR-USERNAME` with your actual GitHub username. Do not paste the example URL unchanged.

## Deploy with Streamlit Community Cloud

1. Push the files to your GitHub repository.
2. Open https://share.streamlit.io/ and sign in with GitHub.
3. Choose **Create app**.
4. Select your repository, branch `main`, and entrypoint `app.py`.
5. Click **Deploy** and wait for the app to start.
6. Open the generated public app URL and test the sample inputs.
7. Copy the real deployed URL into the hackathon submission form.

Official guide: https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy

## Suggested live demo script (60–90 seconds)

1. Introduce the problem: scams use urgency, impersonation, and payment pressure.
2. Select “Suspicious bank alert.”
3. Show the risk score and warning signs.
4. Switch to Telugu and show the recommended action.
5. Try the “Possible legitimate message” sample and explain that a low score is not a guarantee of safety.
6. State the current limitations and next steps: labeled-data evaluation, stronger URL reputation integration, privacy review, and more languages.

## Privacy and safety

- Do not paste real passwords, OTPs, bank details, or private conversations.
- This demo does not need to transmit message content to an external AI API.
- Do not click suspicious URLs as part of testing.
- Avoid claiming 100% accuracy or calling the score a probability.
