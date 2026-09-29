/**
 * PhishGuard AI - Feature Extraction Engine
 * Parses and computes lexical, structural, statistical, and semantic features
 * strictly treating the input as a text string (ZERO execution, ZERO network fetches).
 */

import { CONFIG } from './config.js';

export class FeatureExtractor {
  /**
   * Calculate Shannon Entropy of a string to detect randomized/DGA strings
   * @param {string} str 
   * @returns {number}
   */
  static calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return Number(entropy.toFixed(3));
  }

  /**
   * Sanitizes and parses a raw URL string without executing any external requests
   * @param {string} rawInput 
   * @returns {Object} Cleaned URL components
   */
  static parseUrlSafe(rawInput) {
    let clean = (rawInput || '').trim();
    if (!clean) {
      throw new Error("Please enter a valid URL to analyze.");
    }

    // Check if protocol is missing; prepend http:// strictly for standard text parsing
    let hasProtocol = /^https?:\/\//i.test(clean);
    let parsingUrl = hasProtocol ? clean : `http://${clean}`;

    let parsed;
    try {
      parsed = new URL(parsingUrl);
    } catch (e) {
      // Fallback manual regex parser if URL constructor fails on unconventional formats
      const regex = /^(?:(https?:)\/\/)?(?:([^:@]+)(?::([^:@]+))?@)?([^\/:]+)(?::(\d+))?(\/[^?#]*)?(?:\?([^#]*))?(?:#(.*))?$/i;
      const match = parsingUrl.match(regex);
      if (!match) {
        throw new Error("Malformed URL structure could not be parsed safely.");
      }
      parsed = {
        protocol: (match[1] || 'http:').toLowerCase(),
        username: match[2] || '',
        password: match[3] || '',
        hostname: (match[4] || '').toLowerCase(),
        port: match[5] || '',
        pathname: match[6] || '/',
        search: match[7] ? `?${match[7]}` : '',
        hash: match[8] ? `#${match[8]}` : '',
        href: parsingUrl
      };
    }

    return {
      raw: clean,
      protocol: parsed.protocol.replace(':', '').toLowerCase(),
      hostname: parsed.hostname.toLowerCase(),
      port: parsed.port || '',
      pathname: parsed.pathname || '/',
      search: parsed.search || '',
      hash: parsed.hash || '',
      fullUrl: parsed.href
    };
  }

  /**
   * Extracts comprehensive features for machine learning analysis
   * @param {string} rawUrl 
   * @returns {Object} Extracted feature set and human-readable triggers
   */
  static extractFeatures(rawUrl) {
    const parsed = this.parseUrlSafe(rawUrl);
    const { raw, protocol, hostname, port, pathname, search, fullUrl } = parsed;

    // 1. IP Address detection (IPv4, IPv6, Hex/Octal obfuscated)
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^\[?[a-fA-F0-9:]+\]?$/;
    const isIpAddress = ipv4Regex.test(hostname) || (hostname.includes(':') && ipv6Regex.test(hostname));

    // 2. Length Metrics
    const urlLength = raw.length;
    const hostnameLength = hostname.length;
    const pathLength = pathname.length;
    const queryLength = search.length;
    const isExtremelyLong = urlLength > 75;
    const isExtremelyLongPath = pathLength > 50;

    // 3. Subdomain and Domain Decomposition
    const hostParts = hostname.split('.');
    const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';
    const mainDomain = hostParts.length >= 2 ? `${hostParts[hostParts.length - 2]}.${tld}` : hostname;
    const subdomainCount = Math.max(0, hostParts.length - 2);
    const excessiveSubdomains = subdomainCount >= 3;
    const dotCount = (hostname.match(/\./g) || []).length;
    const hasTooManyDots = dotCount >= 4;

    // 4. Special Character Obfuscation
    const hasAtSymbol = raw.includes('@');
    const hasDoubleSlashRedirect = pathname.includes('//') || raw.slice(8).includes('//');
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const hasMultipleHyphens = hyphenCount >= 2;
    const hexCount = (raw.match(/%[0-9a-fA-F]{2}/g) || []).length;
    const hasHexEncoding = hexCount >= 2;

    // 5. Entropy calculation
    const hostnameEntropy = this.calculateEntropy(hostname);
    const urlEntropy = this.calculateEntropy(raw);
    const highEntropy = hostnameEntropy > 3.8 || urlEntropy > 4.6;

    // 6. Punycode & Homoglyph Attacks
    const hasPunycodeHomograph = hostname.startsWith('xn--') || hostname.includes('.xn--');

    // 7. Suspicious TLD check
    const isSuspiciousTld = CONFIG.SUSPICIOUS_TLDS.includes(tld.toLowerCase());

    // 8. Suspicious Phishing Keywords
    const lowerRaw = raw.toLowerCase();
    const detectedKeywords = [];
    CONFIG.SUSPICIOUS_KEYWORDS.forEach(kw => {
      if (lowerRaw.includes(kw)) {
        detectedKeywords.push(kw);
      }
    });
    const hasSuspiciousKeyword = detectedKeywords.length > 0;

    // 9. Protocol and Port Inspection
    const isHttpInsteadOfHttps = protocol === 'http';
    const nonStandardPorts = ['8080', '8888', '2082', '2083', '8443', '3000', '5000', '8000'];
    const hasSuspiciousPort = port !== '' && nonStandardPorts.includes(port);

    // 10. Nested URL Injection
    const hasNestedUrl = /(?:https?:\/\/|www\.)/i.test(raw.slice(raw.indexOf(hostname) + hostname.length));

    // 11. Known URL Shortener
    const isShortener = CONFIG.SHORTENER_DOMAINS.some(shortener => hostname === shortener || hostname.endsWith(`.${shortener}`));

    // 12. Trusted Domain Check (for baseline reputation)
    const isKnownTrustedDomain = CONFIG.TRUSTED_DOMAINS.some(td => hostname === td || hostname.endsWith(`.${td}`));

    // Compile Feature Vector
    const features = {
      isIpAddress,
      excessiveSubdomains,
      hasAtSymbol,
      hasDoubleSlashRedirect,
      isExtremelyLong,
      isExtremelyLongPath,
      highEntropy,
      hasSuspiciousKeyword,
      hasMultipleHyphens,
      isSuspiciousTld,
      hasPunycodeHomograph,
      hasHexEncoding,
      hasTooManyDots,
      isHttpInsteadOfHttps,
      hasSuspiciousPort,
      hasNestedUrl,
      isShortener,
      isKnownTrustedDomain
    };

    // Human-readable signals for the "Why?" result explanation
    const triggers = [];
    if (isIpAddress) triggers.push({ code: "IP_HOST", label: "IP address used as hostname instead of a verified domain" });
    if (hasAtSymbol) triggers.push({ code: "AT_SYMBOL", label: "Embedded '@' symbol (credential injection / spoofing vector)" });
    if (hasDoubleSlashRedirect) triggers.push({ code: "DOUBLE_SLASH", label: "Suspicious '//' path structure (open redirect trick)" });
    if (excessiveSubdomains) triggers.push({ code: "EXCESS_SUBDOMAINS", label: `Excessive subdomains (${subdomainCount} levels detected)` });
    if (hasSuspiciousKeyword) triggers.push({ code: "KEYWORDS", label: `Suspicious keyword(s) detected: "${detectedKeywords.slice(0, 3).join('", "')}"` });
    if (isSuspiciousTld) triggers.push({ code: "RISKY_TLD", label: `High-risk top-level domain (.${tld}) frequently used in disposable scams` });
    if (hasPunycodeHomograph) triggers.push({ code: "PUNYCODE", label: "Punycode (xn--) internationalized domain — potential homograph spoof" });
    if (isExtremelyLong) triggers.push({ code: "LONG_URL", label: `Unusually long URL (${urlLength} characters)` });
    if (isExtremelyLongPath) triggers.push({ code: "LONG_PATH", label: `Excessively deep URL path (${pathLength} characters)` });
    if (hasMultipleHyphens) triggers.push({ code: "HYPHENS", label: `Multiple hyphens in domain (${hyphenCount}) mimicking trusted brand names` });
    if (highEntropy) triggers.push({ code: "ENTROPY", label: `High algorithmic character randomness (Entropy score: ${hostnameEntropy})` });
    if (hasHexEncoding) triggers.push({ code: "HEX_ENCODING", label: `Hex / URL encoding obfuscation detected (${hexCount} encoded sequences)` });
    if (hasNestedUrl) triggers.push({ code: "NESTED_URL", label: "Nested HTTP link embedded inside query/path" });
    if (hasSuspiciousPort) triggers.push({ code: "CUSTOM_PORT", label: `Non-standard web port (:${port})` });
    if (isHttpInsteadOfHttps) triggers.push({ code: "NO_TLS", label: "Insecure HTTP protocol (no TLS encryption)" });
    if (isShortener) triggers.push({ code: "SHORTENER", label: "URL shortener masking true destination host" });

    return {
      rawUrl: raw,
      parsed,
      metrics: {
        urlLength,
        hostnameLength,
        pathLength,
        queryLength,
        subdomainCount,
        dotCount,
        hyphenCount,
        hostnameEntropy,
        urlEntropy,
        tld,
        detectedKeywords
      },
      features,
      triggers
    };
  }
}
