/**
 * PhishGuard AI - Central Configuration
 * All thresholds, safety parameters, and feature scoring rules are configured here.
 */

export const CONFIG = {
  APP_NAME: "PhishGuard AI",
  VERSION: "2.4.0",
  
  // Risk Score Thresholds (0-100 scale)
  THRESHOLDS: {
    LOW_MAX: 30,      // 0 - 30 => Low Risk (Likely Safe)
    MEDIUM_MAX: 70,   // 31 - 70 => Medium Risk (Suspicious)
    HIGH_MAX: 100     // 71 - 100 => High Risk (Potential Threat)
  },

  // UI Status Mapping & Exact Prescribed Copy
  STATUS_DEFINITIONS: {
    LOW: {
      category: "LOW",
      badgeText: "Likely Safe",
      title: "Likely Safe to Open",
      riskLevel: "Low",
      colorClass: "status-safe",
      colorHex: "#10b981",
      icon: "shield-check",
      description: "Based on the analyzed URL characteristics, this URL appears low-risk. However, no automated detector can guarantee that a website is completely safe.",
      whatItMeans: "The URL does not show significant suspicious characteristics according to the trained model. This does not guarantee that the website is completely safe.",
      actionPrimary: "Continue to Website",
      actionSecondary: "Scan Another URL",
      actionType: "SAFE_PROCEED"
    },
    MEDIUM: {
      category: "MEDIUM",
      badgeText: "Suspicious",
      title: "Suspicious — Open With Caution",
      riskLevel: "Medium",
      colorClass: "status-suspicious",
      colorHex: "#f59e0b",
      icon: "alert-triangle",
      description: "This URL contains characteristics that may be associated with suspicious websites. Avoid entering passwords, payment information, or other sensitive information.",
      whatItMeans: "The URL contains characteristics that require caution. Avoid providing sensitive information until the website's legitimacy has been independently verified.",
      actionPrimary: "Proceed With Caution",
      actionSecondary: "Review Again",
      actionType: "CAUTION_PROCEED"
    },
    HIGH: {
      category: "HIGH",
      badgeText: "Potential Threat",
      title: "Potential Threat — Do Not Open",
      riskLevel: "High",
      colorClass: "status-threat",
      colorHex: "#ef4444",
      icon: "shield-alert",
      description: "The URL has multiple characteristics associated with potentially malicious or phishing websites. Avoid opening it or entering any personal information.",
      whatItMeans: "The URL contains multiple characteristics commonly associated with phishing or malicious URLs. Avoid opening the link and do not provide credentials or payment information.",
      actionPrimary: "Avoid Opening This URL",
      actionSecondary: "Copy Safety Report",
      actionType: "BLOCKED"
    }
  },

  // Machine Learning Model Weights for Lexical & Heuristic Features
  // Calibrated against phishing URL datasets (ISCX / PhishTank / OpenPhish feature metrics)
  MODEL_WEIGHTS: {
    isIpAddress: 35.0,              // Direct IP in hostname is a massive red flag
    excessiveSubdomains: 18.0,      // > 3 subdomains
    hasAtSymbol: 24.0,              // @ symbol in URL (browser credential spoofing)
    hasDoubleSlashRedirect: 22.0,   // // in path (redirect trick)
    isExtremelyLong: 15.0,          // URL length > 75 chars
    isExtremelyLongPath: 12.0,      // Path > 50 chars
    highEntropy: 14.0,              // Random / algorithmic generation (DGA)
    hasSuspiciousKeyword: 20.0,     // login, verify, secure, banking, paypal, update, etc.
    hasMultipleHyphens: 12.0,       // Domain contains 2+ hyphens (brand-spoofing)
    isSuspiciousTld: 22.0,          // .top, .xyz, .tk, .ml, .ga, .cf, .gq, .buzz, .cc abuse
    hasPunycodeHomograph: 30.0,     // xn-- homoglyph attack
    hasHexEncoding: 14.0,           // %20, %2f, %40 obfuscation
    hasTooManyDots: 12.0,           // > 4 dots in hostname
    isHttpInsteadOfHttps: 8.0,      // Missing modern TLS protocol
    hasSuspiciousPort: 25.0,        // Explicit unusual port (:8080, :8888, :2082, etc.)
    hasNestedUrl: 26.0,             // Contains another http:// or https:// inside query/path
    isShortener: 10.0               // bit.ly, tinyurl (masks final destination)
  },

  // Suspicious TLD list frequently abused in automated phishing kits
  SUSPICIOUS_TLDS: [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "loan", 
    "buzz", "gdn", "icu", "surf", "rest", "cam", "fit", "monster", "bar", "live"
  ],

  // Common high-target phishing keywords
  SUSPICIOUS_KEYWORDS: [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "secure",
    "account", "update", "banking", "authenticate", "confirm", "wallet",
    "support", "security", "recovery", "password", "credential", "suspend",
    "appleid", "paypal", "netflix", "microsoft", "google-security", "chase"
  ],

  // Known trusted top-level authoritative domains (for baseline comparison)
  TRUSTED_DOMAINS: [
    "google.com", "microsoft.com", "apple.com", "github.com", "amazon.com",
    "wikipedia.org", "mozilla.org", "cloudflare.com", "gov", "edu"
  ],

  // URL Shorteners
  SHORTENER_DOMAINS: [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rebrand.ly", "cutt.ly"
  ],

  // Sample URLs for Demonstration and Testing
  SAMPLE_URLS: [
    {
      label: "Safe: Official Tech Portal",
      url: "https://www.github.com/features/security",
      expected: "LOW"
    },
    {
      label: "Safe: Educational Resource",
      url: "https://developer.mozilla.org/en-US/docs/Web/Security",
      expected: "LOW"
    },
    {
      label: "Suspicious: Masked Shortener Link",
      url: "http://bit.ly/3xY7z9q-verify-auth",
      expected: "MEDIUM"
    },
    {
      label: "Suspicious: Unverified Domain & Hyphens",
      url: "http://my-secure-portal-app.net/dashboard/view",
      expected: "MEDIUM"
    },
    {
      label: "Threat: Direct IP with Login Keyword",
      url: "http://192.168.1.104/secure-banking-verification/login.php?user=account_verify",
      expected: "HIGH"
    },
    {
      label: "Threat: Nested URL & Credential Spoof (@)",
      url: "http://paypal.com@verify-account-security-update.tk//login/auth/session",
      expected: "HIGH"
    },
    {
      label: "Threat: Punycode Homograph & Hyphens",
      url: "https://xn--appl-9oa.com-security-alert-center.top/authenticate",
      expected: "HIGH"
    }
  ]
};
