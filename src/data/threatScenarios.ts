import { Mail, Link2, UserX, AlertTriangle, Bug } from "lucide-react";

export type QuickAction = {
  label: string;
  value: string;
};

export type Question = {
  id: string;
  text: string;
  quickActions: QuickAction[];
};

export type RecoveryStep = {
  title: string;
  description: string;
  priority: "critical" | "high" | "medium";
};

export type ThreatScenario = {
  id: string;
  title: string;
  description: string;
  icon: typeof Mail;
  color: "primary" | "accent" | "destructive" | "warning";
  questions: Question[];
  getRecoverySteps: (answers: Record<string, string>) => RecoveryStep[];
  securityNotes: string[];
};

export const threatScenarios: ThreatScenario[] = [
  {
    id: "phishing",
    title: "Phishing Email",
    description: "Suspicious email asking for credentials, payments, or personal info",
    icon: Mail,
    color: "warning",
    questions: [
      {
        id: "clicked",
        text: "Did you click any links or download attachments from the suspicious email?",
        quickActions: [
          { label: "Yes, clicked a link", value: "clicked_link" },
          { label: "Yes, downloaded file", value: "downloaded" },
          { label: "No, just opened email", value: "opened_only" },
          { label: "Not sure", value: "unsure" },
        ],
      },
      {
        id: "credentials",
        text: "Did you enter any login credentials, passwords, or personal information?",
        quickActions: [
          { label: "Yes, entered password", value: "entered_password" },
          { label: "Yes, personal info", value: "entered_personal" },
          { label: "No", value: "no" },
          { label: "Don't remember", value: "unsure" },
        ],
      },
      {
        id: "device",
        text: "What device were you using when this happened?",
        quickActions: [
          { label: "Work computer", value: "work_computer" },
          { label: "Personal computer", value: "personal_computer" },
          { label: "Phone/Tablet", value: "mobile" },
        ],
      },
    ],
    getRecoverySteps: (answers) => {
      const steps: RecoveryStep[] = [];
      
      if (answers.credentials === "entered_password" || answers.credentials === "entered_personal") {
        steps.push({
          title: "Change All Compromised Passwords Immediately",
          description: "Change the password for the account you entered credentials for, plus any other accounts using the same password. Use a unique, strong password for each.",
          priority: "critical",
        });
        steps.push({
          title: "Enable Two-Factor Authentication",
          description: "Turn on 2FA/MFA for all accounts, especially email, banking, and social media. Use an authenticator app rather than SMS when possible.",
          priority: "critical",
        });
      }

      if (answers.clicked === "downloaded") {
        steps.push({
          title: "Run Full Antivirus Scan",
          description: "Immediately run a full system scan with your antivirus software. If you don't have one, download Malwarebytes or use Windows Defender.",
          priority: "critical",
        });
        steps.push({
          title: "Delete Downloaded Files",
          description: "Locate and permanently delete any files downloaded from the suspicious email. Empty your recycle bin/trash afterward.",
          priority: "high",
        });
      }

      if (answers.clicked === "clicked_link") {
        steps.push({
          title: "Clear Browser Data",
          description: "Clear cookies, cache, and browsing history for the browser used. Consider clearing saved passwords too.",
          priority: "high",
        });
      }

      steps.push({
        title: "Report the Phishing Email",
        description: "Forward the email to your IT department (if work) or report it to reportphishing@apwg.org. Mark it as spam/phishing in your email client.",
        priority: "high",
      });

      if (answers.device === "work_computer") {
        steps.push({
          title: "Notify Your IT Department",
          description: "Contact your IT/security team immediately. They may need to scan the network and check for broader compromise.",
          priority: "critical",
        });
      }

      steps.push({
        title: "Monitor Your Accounts",
        description: "Check for unauthorized logins, password reset emails, or suspicious activity across your accounts over the next 30 days.",
        priority: "medium",
      });

      return steps;
    },
    securityNotes: [
      "Legitimate organizations never ask for passwords via email",
      "Check sender addresses carefully — phishing often uses look-alike domains",
      "When in doubt, navigate to websites directly instead of clicking email links",
    ],
  },
  {
    id: "malicious-link",
    title: "Malicious Link",
    description: "Clicked a suspicious link from social media, text, or unknown source",
    icon: Link2,
    color: "destructive",
    questions: [
      {
        id: "source",
        text: "Where did you encounter the suspicious link?",
        quickActions: [
          { label: "Social media post", value: "social_media" },
          { label: "Text message/SMS", value: "sms" },
          { label: "Chat/messaging app", value: "chat" },
          { label: "Website pop-up", value: "popup" },
        ],
      },
      {
        id: "action",
        text: "What happened after you clicked the link?",
        quickActions: [
          { label: "Redirected to fake site", value: "fake_site" },
          { label: "Download started", value: "download" },
          { label: "Nothing obvious", value: "nothing" },
          { label: "Browser froze/crashed", value: "crash" },
        ],
      },
      {
        id: "info_entered",
        text: "Did you enter any information on the page you were redirected to?",
        quickActions: [
          { label: "Yes, login info", value: "login" },
          { label: "Yes, payment/card info", value: "payment" },
          { label: "No, closed immediately", value: "closed" },
          { label: "Not sure", value: "unsure" },
        ],
      },
    ],
    getRecoverySteps: (answers) => {
      const steps: RecoveryStep[] = [];

      if (answers.info_entered === "payment") {
        steps.push({
          title: "Contact Your Bank Immediately",
          description: "Call your bank or credit card company to report potential fraud. Request a card freeze or replacement. Monitor for unauthorized charges.",
          priority: "critical",
        });
      }

      if (answers.info_entered === "login") {
        steps.push({
          title: "Change Compromised Passwords Now",
          description: "Change passwords for any accounts whose credentials you entered. Enable 2FA on all critical accounts.",
          priority: "critical",
        });
      }

      if (answers.action === "download") {
        steps.push({
          title: "Don't Open Downloaded Files",
          description: "If a file was downloaded, do NOT open it. Delete it immediately and run a full antivirus scan on your device.",
          priority: "critical",
        });
      }

      steps.push({
        title: "Clear Browser Data & Sessions",
        description: "Clear all cookies, cache, and site data. Log out of all browser sessions and sign back in with fresh credentials.",
        priority: "high",
      });

      if (answers.action === "crash") {
        steps.push({
          title: "Check for Malware Installation",
          description: "A browser crash could indicate exploit attempt. Run a full system scan and check for unknown programs or browser extensions.",
          priority: "critical",
        });
      }

      steps.push({
        title: "Report the Malicious Link",
        description: "Report the link to Google Safe Browsing (safebrowsing.google.com) and the platform where you found it.",
        priority: "medium",
      });

      return steps;
    },
    securityNotes: [
      "Hover over links to preview URLs before clicking",
      "Shortened URLs (bit.ly, tinyurl) can hide malicious destinations",
      "If an offer seems too good to be true, it probably is",
    ],
  },
  {
    id: "account-takeover",
    title: "Account Takeover",
    description: "Locked out of an account or noticed unauthorized access",
    icon: UserX,
    color: "destructive",
    questions: [
      {
        id: "account_type",
        text: "Which type of account has been compromised?",
        quickActions: [
          { label: "Email account", value: "email" },
          { label: "Social media", value: "social" },
          { label: "Banking/Financial", value: "banking" },
          { label: "Work/Corporate", value: "work" },
        ],
      },
      {
        id: "access",
        text: "Can you still access the account?",
        quickActions: [
          { label: "Yes, but see strange activity", value: "partial" },
          { label: "No, completely locked out", value: "locked" },
          { label: "Yes, got alert about new login", value: "alert" },
        ],
      },
      {
        id: "linked",
        text: "Is this account linked to other services (e.g., used for SSO/login)?",
        quickActions: [
          { label: "Yes, many services", value: "many" },
          { label: "Yes, a few", value: "few" },
          { label: "No, standalone", value: "standalone" },
          { label: "Not sure", value: "unsure" },
        ],
      },
    ],
    getRecoverySteps: (answers) => {
      const steps: RecoveryStep[] = [];

      if (answers.access === "locked") {
        steps.push({
          title: "Initiate Account Recovery",
          description: "Use the platform's official account recovery process. Verify your identity through backup email, phone, or ID verification.",
          priority: "critical",
        });
      } else {
        steps.push({
          title: "Change Password Immediately",
          description: "Change your password right now. Use a strong, unique password you haven't used before. At least 16 characters with mixed types.",
          priority: "critical",
        });
        steps.push({
          title: "Revoke All Active Sessions",
          description: "Go to security settings and sign out all other devices/sessions. This kicks the attacker out immediately.",
          priority: "critical",
        });
      }

      steps.push({
        title: "Enable Two-Factor Authentication",
        description: "Set up 2FA using an authenticator app (Google Authenticator, Authy). Avoid SMS-based 2FA if possible.",
        priority: "critical",
      });

      if (answers.account_type === "banking") {
        steps.push({
          title: "Contact Your Financial Institution",
          description: "Call your bank immediately. Request account freeze, review recent transactions, and dispute unauthorized ones.",
          priority: "critical",
        });
        steps.push({
          title: "Place Fraud Alert on Credit Reports",
          description: "Contact one of the three credit bureaus (Equifax, Experian, TransUnion) to place a fraud alert. They'll notify the others.",
          priority: "high",
        });
      }

      if (answers.linked === "many" || answers.linked === "few") {
        steps.push({
          title: "Secure All Linked Accounts",
          description: "Change passwords on all accounts that use this compromised account for login. Review and revoke unauthorized app permissions.",
          priority: "high",
        });
      }

      if (answers.account_type === "work") {
        steps.push({
          title: "Alert IT Security Team",
          description: "Notify your organization's IT/security team immediately. Corporate accounts may have access to sensitive data.",
          priority: "critical",
        });
      }

      steps.push({
        title: "Review Account Activity Log",
        description: "Check login history, connected devices, and recent changes. Document everything suspicious for potential reporting.",
        priority: "medium",
      });

      return steps;
    },
    securityNotes: [
      "Use a password manager to generate and store unique passwords",
      "Never reuse passwords across multiple accounts",
      "Set up login alerts/notifications for critical accounts",
    ],
  },
  {
    id: "scareware",
    title: "Scareware Pop-up",
    description: "Fake virus warning, tech support scam, or urgent security alert",
    icon: AlertTriangle,
    color: "warning",
    questions: [
      {
        id: "interaction",
        text: "How did you interact with the scareware pop-up?",
        quickActions: [
          { label: "Closed it immediately", value: "closed" },
          { label: "Called the number shown", value: "called" },
          { label: "Clicked a button on it", value: "clicked" },
          { label: "Gave remote access", value: "remote_access" },
        ],
      },
      {
        id: "payment",
        text: "Did you make any payments or share financial information?",
        quickActions: [
          { label: "Yes, credit/debit card", value: "card" },
          { label: "Yes, gift cards/crypto", value: "gift_card" },
          { label: "No", value: "no" },
        ],
      },
      {
        id: "installed",
        text: "Were you asked to install any software?",
        quickActions: [
          { label: "Yes, installed it", value: "installed" },
          { label: "Yes, but didn't install", value: "declined" },
          { label: "No", value: "no" },
        ],
      },
    ],
    getRecoverySteps: (answers) => {
      const steps: RecoveryStep[] = [];

      if (answers.interaction === "remote_access") {
        steps.push({
          title: "Disconnect from Internet Immediately",
          description: "Unplug ethernet or disable Wi-Fi RIGHT NOW. The scammer may still have access to your computer.",
          priority: "critical",
        });
        steps.push({
          title: "Change All Passwords from Another Device",
          description: "Using a phone or different computer, change passwords for all accounts accessible from the compromised device.",
          priority: "critical",
        });
        steps.push({
          title: "Remove Remote Access Software",
          description: "Uninstall TeamViewer, AnyDesk, or any remote access tool installed during the scam. Check startup programs too.",
          priority: "critical",
        });
      }

      if (answers.installed === "installed") {
        steps.push({
          title: "Uninstall Suspicious Software",
          description: "Go to Add/Remove Programs and uninstall any recently installed unknown software. Run Malwarebytes for thorough cleanup.",
          priority: "critical",
        });
      }

      if (answers.payment === "card") {
        steps.push({
          title: "Contact Bank to Dispute Charges",
          description: "Call your bank/credit card company immediately. Report fraud, dispute the charge, and request a new card number.",
          priority: "critical",
        });
      }

      if (answers.payment === "gift_card") {
        steps.push({
          title: "Report Gift Card Fraud",
          description: "Contact the gift card issuer with the card numbers. Report to FTC at reportfraud.ftc.gov. Recovery may be limited.",
          priority: "high",
        });
      }

      steps.push({
        title: "Run Full Malware Scan",
        description: "Run a complete system scan with reputable antivirus. Consider using multiple tools: Windows Defender + Malwarebytes.",
        priority: "high",
      });

      if (answers.interaction === "called") {
        steps.push({
          title: "Block the Scam Number",
          description: "Block the phone number and report it to the FTC. Never call numbers displayed in pop-up warnings.",
          priority: "medium",
        });
      }

      steps.push({
        title: "Install an Ad Blocker",
        description: "Install uBlock Origin to prevent malicious ads and pop-ups. Keep your browser and OS updated.",
        priority: "medium",
      });

      return steps;
    },
    securityNotes: [
      "Real antivirus software never shows browser pop-ups asking you to call a number",
      "Microsoft, Apple, and Google will never call you about a virus",
      "Force-close your browser (Alt+F4 / Cmd+Q) if a pop-up won't close normally",
    ],
  },
  {
    id: "malware",
    title: "Malware Infection",
    description: "Computer acting strange, running slow, or showing unexpected behavior",
    icon: Bug,
    color: "destructive",
    questions: [
      {
        id: "symptoms",
        text: "What symptoms are you experiencing?",
        quickActions: [
          { label: "Computer very slow", value: "slow" },
          { label: "Strange pop-ups", value: "popups" },
          { label: "Programs opening by themselves", value: "auto_programs" },
          { label: "Files encrypted/ransomware", value: "ransomware" },
        ],
      },
      {
        id: "recent_action",
        text: "What did you do recently that might have caused the infection?",
        quickActions: [
          { label: "Downloaded software", value: "download" },
          { label: "Opened email attachment", value: "email" },
          { label: "Visited suspicious site", value: "website" },
          { label: "Used USB/external drive", value: "usb" },
        ],
      },
      {
        id: "data_access",
        text: "Does this device have access to sensitive data or work systems?",
        quickActions: [
          { label: "Yes, work/corporate data", value: "work" },
          { label: "Yes, personal banking", value: "banking" },
          { label: "Yes, personal files only", value: "personal" },
          { label: "No sensitive data", value: "none" },
        ],
      },
    ],
    getRecoverySteps: (answers) => {
      const steps: RecoveryStep[] = [];

      if (answers.symptoms === "ransomware") {
        steps.push({
          title: "DO NOT Pay the Ransom",
          description: "Paying does not guarantee file recovery and funds criminal activity. Disconnect from network immediately to prevent spread.",
          priority: "critical",
        });
        steps.push({
          title: "Check No More Ransom Project",
          description: "Visit nomoreransom.org for free decryption tools. Identify the ransomware variant and check if a decryptor exists.",
          priority: "critical",
        });
        steps.push({
          title: "Report to Law Enforcement",
          description: "File a report with IC3 (ic3.gov) or your local cyber crime unit. Keep all ransom notes and evidence.",
          priority: "high",
        });
      }

      steps.push({
        title: "Boot into Safe Mode",
        description: "Restart in Safe Mode (hold Shift while restarting on Windows). This prevents most malware from running.",
        priority: "critical",
      });

      steps.push({
        title: "Run Multiple Malware Scans",
        description: "Run Windows Defender offline scan, then Malwarebytes. For stubborn infections, try HitmanPro or ESET Online Scanner.",
        priority: "critical",
      });

      if (answers.data_access === "work") {
        steps.push({
          title: "Disconnect from Corporate Network",
          description: "Immediately disconnect from VPN and work networks. Notify IT security. The infection could spread to other systems.",
          priority: "critical",
        });
      }

      if (answers.data_access === "banking") {
        steps.push({
          title: "Secure Financial Accounts",
          description: "From a clean device, change banking passwords and enable 2FA. Monitor accounts for unauthorized transactions.",
          priority: "critical",
        });
      }

      steps.push({
        title: "Update All Software",
        description: "After cleanup, update your OS, browser, and all applications. Outdated software is a common infection vector.",
        priority: "high",
      });

      steps.push({
        title: "Restore from Clean Backup",
        description: "If available, restore from a backup made before the infection. Ensure the backup itself isn't compromised.",
        priority: "medium",
      });

      steps.push({
        title: "Consider Clean OS Reinstall",
        description: "For severe infections, a clean OS reinstall is the most reliable fix. Back up important files first (scan them for malware).",
        priority: "medium",
      });

      return steps;
    },
    securityNotes: [
      "Keep your operating system and software up to date",
      "Only download software from official sources",
      "Maintain regular backups using the 3-2-1 rule (3 copies, 2 media types, 1 offsite)",
    ],
  },
];
