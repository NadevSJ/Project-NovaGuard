"""Manually curated Sri Lankan scam and legitimate-message samples.

These samples are paraphrased from CERT.LK advisories and Sri Lankan news
reports on financial fraud. They are not copied verbatim. The samples cover
the local threat landscape that PhishTank/OpenPhish/UCI do not capture (Sinhala
brand impersonation, .lk-shaped lookalike domains, Middle-East job lures).
"""

from __future__ import annotations

from typing import Any

CERT_LK_SAMPLES: list[dict[str, Any]] = [
    # ------------------------------------------------ FAKE BANK SMS (5)
    {
        "id": "CERTLK-BANK-001",
        "input_type": "text",
        "input": (
            "URGENT: Your BOC account has been suspended due to unusual "
            "activity. Verify your PIN at http://boc-secure-lk.ddns.net "
            "within 24 hours or your account will be blocked."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [90, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "fake_bank_sms",
        "red_flags": [
            "Impersonates Bank of Ceylon (BOC)",
            "Asks for PIN via SMS link — banks never do this",
            "Uses urgency: 24-hour deadline",
            "Non-bank domain (ddns.net) instead of boc.lk",
        ],
        "notes": "Classic BOC PIN-harvest phishing pattern reported by CERT.LK.",
    },
    {
        "id": "CERTLK-BANK-002",
        "input_type": "text",
        "input": (
            "Sampath Bank Alert: Your online banking has been blocked. "
            "Reactivate immediately by confirming your NIC and password at "
            "https://sampath-secure.online/login"
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [88, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "fake_bank_sms",
        "red_flags": [
            "Impersonates Sampath Bank",
            "Requests NIC + password through link",
            "Domain sampath-secure.online (real domain is sampath.lk)",
            "Urgency: 'immediately'",
        ],
        "notes": "Lookalike domain on .online TLD targeting Sampath customers.",
    },
    {
        "id": "CERTLK-BANK-003",
        "input_type": "text",
        "input": (
            "Commercial Bank: Your credit card has been temporarily "
            "suspended. To restore access, verify your CVV and OTP at "
            "http://combank-verify.xyz now."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [92, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "fake_bank_sms",
        "red_flags": [
            "Impersonates Commercial Bank of Ceylon",
            "Asks for CVV and OTP — never legitimate over SMS",
            ".xyz domain instead of combank.lk",
            "Urgency: 'now'",
        ],
        "notes": "CVV+OTP harvest aimed at card fraud.",
    },
    {
        "id": "CERTLK-BANK-004",
        "input_type": "text",
        "input": (
            "Peoples Bank Notice: Suspicious login detected on your account. "
            "Confirm your identity at https://peoples-bank-lk.com/secure "
            "within 12 hours to avoid permanent suspension."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [86, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "fake_bank_sms",
        "red_flags": [
            "Impersonates People's Bank",
            "Domain peoples-bank-lk.com (real: peoplesbank.lk)",
            "12-hour deadline (urgency)",
            "Threat of permanent suspension",
        ],
        "notes": "Identity-confirmation pretext, common in late-night blast SMS.",
    },
    {
        "id": "CERTLK-BANK-005",
        "input_type": "text",
        "input": (
            "NSB Alert: Your savings account has been temporarily blocked. "
            "Verify your account number and ATM PIN at http://nsb-verify.lk-secure.net "
            "to reactivate."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [88, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "fake_bank_sms",
        "red_flags": [
            "Impersonates National Savings Bank (NSB)",
            "Requests ATM PIN via link",
            "Deceptive subdomain (lk-secure.net is not an .lk site)",
            "Account-blocked pretext",
        ],
        "notes": "Uses 'lk-' prefix on a non-.lk domain to mimic local trust.",
    },

    # ------------------------------------------------ TELCO SCAMS (3)
    {
        "id": "CERTLK-TELCO-001",
        "input_type": "text",
        "input": (
            "Congratulations! You have been selected for Dialog's 30th "
            "anniversary free Samsung Galaxy giveaway. Click "
            "http://dialog-prize-lk.win to claim within 1 hour."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [85, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "fake_telco_prize",
        "red_flags": [
            "Impersonates Dialog Axiata",
            "Prize-bait language ('free Samsung Galaxy')",
            ".win TLD known for scams",
            "1-hour deadline",
        ],
        "notes": "Recurring 'Dialog anniversary' prize-phish, often via WhatsApp forwards.",
    },
    {
        "id": "CERTLK-TELCO-002",
        "input_type": "text",
        "input": (
            "Mobitel: You won 10 GB free data! Click here to activate: "
            "http://mobitel-freedata.tk before midnight."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [80, 95],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "fake_telco_prize",
        "red_flags": [
            "Impersonates Mobitel",
            "Free-data lure with deadline",
            ".tk TLD (free, frequently abused)",
            "No official Mobitel short code",
        ],
        "notes": "Free-data phishing template circulated on Facebook in 2024.",
    },
    {
        "id": "CERTLK-TELCO-003",
        "input_type": "text",
        "input": (
            "Your Dialog SIM will be deactivated tomorrow due to KYC failure. "
            "Re-verify your NIC and address at http://dialog-kyc-verify.online "
            "to keep your number active."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [85, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "fake_telco_kyc",
        "red_flags": [
            "Impersonates Dialog KYC process",
            "Threat: SIM deactivation",
            "Requests NIC via link",
            ".online TLD lookalike",
        ],
        "notes": "Identity-theft pretext piggybacking on real KYC re-verification drives.",
    },

    # ------------------------------------------------ OVERSEAS JOB SCAMS (3)
    {
        "id": "CERTLK-JOB-001",
        "input_type": "text",
        "input": (
            "Job Vacancy: Hotel Receptionist in Dubai, UAE. Salary Rs.350,000 "
            "per month. No experience required. Apply: "
            "http://gulf-jobs-srilanka.net with NIC and passport copy. "
            "Registration fee Rs.5,000."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [85, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "overseas_job_scam",
        "red_flags": [
            "Asks for a 'registration fee' — licensed agencies never do",
            "Salary far above market for the role",
            "Requests NIC + passport via link",
            "No SLBFE licence number cited",
        ],
        "notes": "Classic Middle-East job scam pattern flagged by SLBFE.",
    },
    {
        "id": "CERTLK-JOB-002",
        "input_type": "text",
        "input": (
            "Urgent Hiring: Cleaners and Drivers in Saudi Arabia. Salary "
            "Rs.250,000. Send your details to http://saudi-jobs-lk.work "
            "and pay Rs.3,500 processing fee via eZ Cash to 077-XXXXXXX."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [85, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "overseas_job_scam",
        "red_flags": [
            "Up-front processing fee via eZ Cash to a personal number",
            "Suspicious .work TLD",
            "Salary above norm",
            "No company name or SLBFE registration",
        ],
        "notes": "Fee-up-front overseas job lure; payment via mobile wallet is the tell.",
    },
    {
        "id": "CERTLK-JOB-003",
        "input_type": "text",
        "input": (
            "Government Job Notification: 1500 vacancies in Sri Lanka Postal "
            "Department. Apply with NIC at http://sl-gov-jobs.info. "
            "Application fee Rs.500."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [80, 95],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "fake_govt_job",
        "red_flags": [
            "Pretends to be a Sri Lankan government recruitment",
            ".info domain — real notices are on .gov.lk",
            "Application fee paid via link",
            "No official Gazette reference",
        ],
        "notes": "Fake government recruitment exploiting graduate unemployment.",
    },

    # ------------------------------------------------ INVESTMENT SCAMS (3)
    {
        "id": "CERTLK-INV-001",
        "input_type": "text",
        "input": (
            "Earn Rs.15,000 daily from home! Forex trading with guaranteed "
            "returns. No experience needed. WhatsApp 0771234567 to join our "
            "VIP signal group today."
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [85, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "investment_scam",
        "red_flags": [
            "'Guaranteed returns' — impossible in real Forex",
            "Daily-earnings claim",
            "Recruitment via personal WhatsApp number",
            "No regulated brokerage cited (CSE / SEC)",
        ],
        "notes": "Recurring Forex signal-group scam, often a pig-butchering funnel.",
    },
    {
        "id": "CERTLK-INV-002",
        "input_type": "text",
        "input": (
            "Double your money in 7 days with our crypto investment platform. "
            "Minimum deposit Rs.10,000. 100% profit guaranteed. Register: "
            "http://lk-crypto-pro.io"
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [90, 100],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "investment_scam",
        "red_flags": [
            "Crypto 'doubler' — textbook Ponzi",
            "'100% profit guaranteed'",
            "Short 7-day deadline",
            "Unregulated platform on .io",
        ],
        "notes": "High-yield investment programme (HYIP) targeting LKR deposits.",
    },
    {
        "id": "CERTLK-INV-003",
        "input_type": "text",
        "input": (
            "Join our exclusive Sinhala-medium share trading group. Make "
            "Rs.50,000/week with insider tips from Colombo Stock Exchange. "
            "Pay Rs.2,500 monthly. Telegram: t.me/cse_insider_lk"
        ),
        "ground_truth_label": "SCAM",
        "ground_truth_score_range": [80, 95],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "investment_scam",
        "red_flags": [
            "Offers 'insider tips' (would be illegal)",
            "Subscription-fee pump-and-dump signal group",
            "Unverifiable Telegram channel",
            "Specific weekly earnings claim",
        ],
        "notes": "Pump-and-dump signal group exploiting retail investors.",
    },

    # ------------------------------------------------ LEGIT BANK NOTIFICATIONS (3)
    {
        "id": "CERTLK-LEGIT-BANK-001",
        "input_type": "text",
        "input": (
            "BOC: Debit of LKR 5,250.00 on 12/05/2026 at KEELLS COLOMBO 03. "
            "Avail Bal LKR 48,300.50. Ref: TXN20260512A. Helpline: 1916."
        ),
        "ground_truth_label": "SAFE",
        "ground_truth_score_range": [0, 10],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "legitimate_bank_sms",
        "red_flags": [],
        "notes": (
            "Normal debit notification: real merchant name, reference number, "
            "and the official BOC helpline 1916. No link, no PIN request."
        ),
    },
    {
        "id": "CERTLK-LEGIT-BANK-002",
        "input_type": "text",
        "input": (
            "Sampath Bank: Your salary credit of LKR 125,000.00 received on "
            "01/05/2026. Ref: SAL20260501. For details call 011-2-303030."
        ),
        "ground_truth_label": "SAFE",
        "ground_truth_score_range": [0, 8],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "legitimate_bank_sms",
        "red_flags": [],
        "notes": "Standard salary credit alert with official Sampath hotline.",
    },
    {
        "id": "CERTLK-LEGIT-BANK-003",
        "input_type": "text",
        "input": (
            "Commercial Bank: Card-not-present transaction of USD 9.99 on "
            "08/05/2026 at NETFLIX. If not authorised, call 011-2-486-486."
        ),
        "ground_truth_label": "SAFE",
        "ground_truth_score_range": [0, 12],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "legitimate_bank_sms",
        "red_flags": [],
        "notes": "Real card-not-present alert; provides the bank's verified hotline rather than a link.",
    },

    # ------------------------------------------------ LEGIT SERVICE NOTIFICATIONS (3)
    {
        "id": "CERTLK-LEGIT-SVC-001",
        "input_type": "text",
        "input": (
            "Dialog: Your prepaid reload of LKR 500 was successful on "
            "10/05/2026. New balance LKR 612.40. Dial #100# for account info."
        ),
        "ground_truth_label": "SAFE",
        "ground_truth_score_range": [0, 8],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "legitimate_telco_sms",
        "red_flags": [],
        "notes": "Standard reload confirmation; no link, references official USSD code.",
    },
    {
        "id": "CERTLK-LEGIT-SVC-002",
        "input_type": "text",
        "input": (
            "Mobitel: Your monthly bill of LKR 2,450 has been generated. "
            "Pay before 25/05/2026. Dial 1717 or visit mobitel.lk."
        ),
        "ground_truth_label": "SAFE",
        "ground_truth_score_range": [0, 10],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "legitimate_telco_sms",
        "red_flags": [],
        "notes": "Bill reminder with the canonical mobitel.lk domain and 1717 hotline.",
    },
    {
        "id": "CERTLK-LEGIT-SVC-003",
        "input_type": "text",
        "input": (
            "CEB: Your electricity bill for April 2026 is LKR 4,120. Due "
            "date 20/05/2026. Pay at ceb.lk or any CEB branch. Acc No: 0123456789."
        ),
        "ground_truth_label": "SAFE",
        "ground_truth_score_range": [0, 10],
        "source": "CERT.LK-manual",
        "source_verified": True,
        "requires_selenium": False,
        "category": "legitimate_utility_sms",
        "red_flags": [],
        "notes": "Routine CEB electricity bill notice using the official ceb.lk domain.",
    },
]


def get_manual_samples() -> list[dict[str, Any]]:
    """Return a fresh copy of the manually curated Sri Lankan sample list."""
    return [dict(sample) for sample in CERT_LK_SAMPLES]
