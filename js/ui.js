/**
 * PhishGuard AI - UI Controller
 * Manages DOM updates, gauge animations, accessible status displays, and safe user actions.
 */

import { CONFIG } from './config.js';

export class UIController {
  constructor() {
    this.initElements();
    this.bindEvents();
    this.currentScanData = null;
  }

  initElements() {
    // Input elements
    this.urlInput = document.getElementById('url-input');
    this.btnScan = document.getElementById('btn-scan');
    this.samplePillsContainer = document.getElementById('sample-pills');

    // Progress elements
    this.scanProgressContainer = document.getElementById('scan-progress');
    this.scanStepTitle = document.getElementById('scan-step-title');
    this.scanStepDesc = document.getElementById('scan-step-desc');
    this.progressBarFill = document.getElementById('progress-bar-fill');

    // Result elements
    this.resultSection = document.getElementById('result-section');
    this.resultCard = document.getElementById('result-card');
    this.statusIconBox = document.getElementById('status-icon-box');
    this.statusSubIndicator = document.getElementById('status-sub-indicator');
    this.statusMainTitle = document.getElementById('status-main-title');
    this.gaugeCircle = document.getElementById('gauge-circle');
    this.gaugeScoreVal = document.getElementById('gauge-score-val');
    this.metricRiskLevel = document.getElementById('metric-risk-level');
    this.metricConfidenceVal = document.getElementById('metric-confidence-val');
    this.scannedUrlDisplay = document.getElementById('scanned-url-display');
    this.safetyStatementBox = document.getElementById('safety-statement-box');
    this.triggersList = document.getElementById('triggers-list');
    this.meaningTextBox = document.getElementById('meaning-text-box');
    this.actionArea = document.getElementById('action-area');

    // Collapsible technical metrics
    this.techAccordionHeader = document.getElementById('tech-accordion-header');
    this.techAccordionBody = document.getElementById('tech-accordion-body');
    this.techAccordionIcon = document.getElementById('tech-accordion-icon');
    this.featureMatrixGrid = document.getElementById('feature-matrix-grid');
    this.threatIntelStatus = document.getElementById('threat-intel-status');
    this.threatIntelFeedList = document.getElementById('threat-intel-feed-list');

    // Safety Confirmation Modal
    this.safetyModalBackdrop = document.getElementById('safety-modal');
    this.modalTitle = document.getElementById('modal-title');
    this.modalBodyText = document.getElementById('modal-body-text');
    this.modalUrlDisplay = document.getElementById('modal-url-display');
    this.btnModalCancel = document.getElementById('btn-modal-cancel');
    this.btnModalConfirm = document.getElementById('btn-modal-confirm');

    // Toast Container
    this.toastContainer = document.getElementById('toast-container');
  }

  bindEvents() {
    // Technical accordion toggle
    if (this.techAccordionHeader) {
      this.techAccordionHeader.addEventListener('click', () => {
        const isOpen = this.techAccordionBody.classList.contains('open');
        this.techAccordionBody.classList.toggle('open', !isOpen);
        this.techAccordionIcon.classList.toggle('rotated', !isOpen);
      });
    }

    // Modal Cancel
    if (this.btnModalCancel) {
      this.btnModalCancel.addEventListener('click', () => this.closeSafetyModal());
    }

    // Modal Backdrop click
    if (this.safetyModalBackdrop) {
      this.safetyModalBackdrop.addEventListener('click', (e) => {
        if (e.target === this.safetyModalBackdrop) {
          this.closeSafetyModal();
        }
      });
    }
  }

  /**
   * Render sample clickable URL pills
   * @param {Function} onSelect 
   */
  renderSamplePills(onSelect) {
    if (!this.samplePillsContainer) return;
    this.samplePillsContainer.innerHTML = '';

    const labelSpan = document.createElement('span');
    labelSpan.className = 'sample-label';
    labelSpan.textContent = 'Quick Test Vectors:';
    this.samplePillsContainer.appendChild(labelSpan);

    CONFIG.SAMPLE_URLS.forEach(sample => {
      const pill = document.createElement('button');
      pill.type = 'button';
      const pillClass = sample.expected === 'LOW' ? 'safe-pill' : (sample.expected === 'MEDIUM' ? 'suspicious-pill' : 'threat-pill');
      pill.className = `sample-pill ${pillClass}`;
      pill.textContent = sample.label;
      pill.title = sample.url;
      pill.addEventListener('click', () => {
        this.urlInput.value = sample.url;
        onSelect(sample.url);
      });
      this.samplePillsContainer.appendChild(pill);
    });
  }

  /**
   * Shows scanning animation steps
   * @param {number} stepIndex 0-3
   */
  updateScanProgress(stepIndex) {
    const steps = [
      { title: "Extracting URL Features...", desc: "Lexical, structural, Shannon entropy, and host analysis", pct: 30 },
      { title: "Machine Learning Analysis...", desc: "Calibrated probability and classification inference", pct: 65 },
      { title: "Threat Intelligence Correlation...", desc: "Decoupled static threat signatures inspection", pct: 90 },
      { title: "Finalizing Safety Assessment...", desc: "Synthesizing explainable risk attribution", pct: 100 }
    ];

    const current = steps[stepIndex] || steps[0];
    this.scanProgressContainer.classList.add('active');
    this.resultSection.classList.remove('active');
    this.btnScan.disabled = true;

    this.scanStepTitle.textContent = current.title;
    this.scanStepDesc.textContent = current.desc;
    this.progressBarFill.style.width = `${current.pct}%`;
  }

  /**
   * Hides scanning animation
   */
  hideScanProgress() {
    this.scanProgressContainer.classList.remove('active');
    this.btnScan.disabled = false;
  }

  /**
   * Renders the prominent final result card with all required sections
   * @param {Object} scanData { extraction, prediction, threatIntel }
   */
  renderResult(scanData) {
    this.currentScanData = scanData;
    const { extraction, prediction, threatIntel } = scanData;
    const status = prediction.status;

    // Reset previous theme classes
    this.resultCard.className = `result-card-prominent ${status.colorClass}`;

    // 1. Icon & Header Indicators
    let iconSvg = '';
    if (prediction.categoryKey === 'LOW') {
      iconSvg = `<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg>`;
      this.statusSubIndicator.innerHTML = `🟢 LIKELY SAFE`;
    } else if (prediction.categoryKey === 'MEDIUM') {
      iconSvg = `<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
      this.statusSubIndicator.innerHTML = `🟠 SUSPICIOUS`;
    } else {
      iconSvg = `<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;
      this.statusSubIndicator.innerHTML = `🔴 POTENTIAL THREAT`;
    }
    this.statusIconBox.innerHTML = iconSvg;
    this.statusMainTitle.textContent = status.title;

    // 2. Risk Metrics & Gauge
    this.animateGauge(prediction.riskScore, status.colorHex);
    this.metricRiskLevel.textContent = prediction.riskLevel.toUpperCase();
    this.metricConfidenceVal.textContent = `${prediction.modelConfidence}%`;

    // 3. Scanned Target Display
    this.scannedUrlDisplay.textContent = extraction.rawUrl;

    // 4. Primary Safety Statement
    this.safetyStatementBox.textContent = status.description;

    // 5. "Why?" Section
    this.renderWhySection(prediction.triggers, prediction.categoryKey);

    // 6. "What does this mean?" Section
    this.meaningTextBox.textContent = status.whatItMeans;

    // 7. Safety Actions (Strict Non-automatic navigation)
    this.renderActionButtons(prediction.categoryKey, extraction.rawUrl);

    // 8. Technical Breakdown & Decoupled Threat Intelligence
    this.renderTechnicalDetails(extraction, threatIntel);

    // Show Result Section with smooth animation
    this.resultSection.classList.add('active');
    this.resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  /**
   * Animate radial SVG gauge for risk score
   */
  animateGauge(score, colorHex) {
    const radius = 36;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (score / 100) * circumference;

    this.gaugeCircle.style.strokeDasharray = `${circumference}`;
    this.gaugeCircle.style.stroke = colorHex;

    // Smooth stroke dashoffset transition
    requestAnimationFrame(() => {
      this.gaugeCircle.style.strokeDashoffset = `${offset}`;
    });

    // Number ticker
    let currentVal = 0;
    const duration = 750;
    const stepTime = 20;
    const steps = duration / stepTime;
    const increment = score / steps;

    const timer = setInterval(() => {
      currentVal += increment;
      if (currentVal >= score) {
        clearInterval(timer);
        this.gaugeScoreVal.textContent = `${score}`;
      } else {
        this.gaugeScoreVal.textContent = `${Math.round(currentVal)}`;
      }
    }, stepTime);
  }

  /**
   * Render "Why?" feature checklist
   */
  renderWhySection(triggers, categoryKey) {
    this.triggersList.innerHTML = '';
    
    if (triggers.length === 0) {
      const item = document.createElement('li');
      item.className = 'trigger-item';
      item.innerHTML = `
        <span class="trigger-icon">✓</span>
        <span>No major suspicious URL characteristics were detected. Standard domain syntax and expected structure verified.</span>
      `;
      this.triggersList.appendChild(item);
      return;
    }

    triggers.forEach(trig => {
      const item = document.createElement('li');
      item.className = 'trigger-item';
      const icon = categoryKey === 'LOW' ? '✓' : (categoryKey === 'MEDIUM' ? '⚠' : '✓');
      item.innerHTML = `
        <span class="trigger-icon">${icon}</span>
        <span>${trig.label}</span>
      `;
      this.triggersList.appendChild(item);
    });
  }

  /**
   * Render Safety Action Buttons based on Risk
   */
  renderActionButtons(categoryKey, rawUrl) {
    this.actionArea.innerHTML = '';

    if (categoryKey === 'LOW') {
      // LOW RISK ACTION: Explicit Confirmation Required
      const btnContinue = document.createElement('button');
      btnContinue.className = 'btn-action-primary btn-safe-continue';
      btnContinue.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
        Continue to Website
      `;
      btnContinue.addEventListener('click', () => {
        this.openSafetyModal({
          title: "Safety Confirmation",
          bodyText: "PhishGuard AI has not found major suspicious characteristics, but automated analysis cannot guarantee safety. Continue?",
          url: rawUrl,
          confirmText: "Yes, Open Website",
          confirmClass: "btn-safe-style",
          onConfirm: () => this.safeNavigate(rawUrl)
        });
      });

      const btnScanAnother = document.createElement('button');
      btnScanAnother.className = 'btn-action-secondary';
      btnScanAnother.innerHTML = `Scan Another URL`;
      btnScanAnother.addEventListener('click', () => {
        this.urlInput.value = '';
        this.urlInput.focus();
      });

      this.actionArea.appendChild(btnContinue);
      this.actionArea.appendChild(btnScanAnother);

    } else if (categoryKey === 'MEDIUM') {
      // MEDIUM RISK ACTION: Review Again & Proceed With Caution
      const btnProceedCaution = document.createElement('button');
      btnProceedCaution.className = 'btn-action-primary btn-caution-continue';
      btnProceedCaution.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        Proceed With Caution
      `;
      btnProceedCaution.addEventListener('click', () => {
        this.openSafetyModal({
          title: "High Caution Warning",
          bodyText: "This URL contains suspicious markers. Do NOT enter sensitive passwords, financial info, or personal credentials if you choose to proceed. Are you sure you wish to continue?",
          url: rawUrl,
          confirmText: "I Understand the Risks, Proceed",
          confirmClass: "btn-caution-style",
          onConfirm: () => this.safeNavigate(rawUrl)
        });
      });

      const btnReview = document.createElement('button');
      btnReview.className = 'btn-action-secondary';
      btnReview.innerHTML = `Review Characteristics Again`;
      btnReview.addEventListener('click', () => {
        this.techAccordionBody.classList.add('open');
        this.techAccordionIcon.classList.add('rotated');
        this.techAccordionHeader.scrollIntoView({ behavior: 'smooth' });
      });

      this.actionArea.appendChild(btnProceedCaution);
      this.actionArea.appendChild(btnReview);

    } else {
      // HIGH RISK ACTION: Strictly NO direct open website button
      const btnBlocked = document.createElement('button');
      btnBlocked.className = 'btn-action-primary btn-threat-block';
      btnBlocked.disabled = true;
      btnBlocked.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>
        ⚠ Avoid Opening This URL
      `;

      const btnCopyReport = document.createElement('button');
      btnCopyReport.className = 'btn-action-secondary';
      btnCopyReport.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        Copy Safety Report
      `;
      btnCopyReport.addEventListener('click', () => this.copyReportToClipboard());

      this.actionArea.appendChild(btnBlocked);
      this.actionArea.appendChild(btnCopyReport);
    }
  }

  /**
   * Renders technical feature inspector and decoupled threat intel
   */
  renderTechnicalDetails(extraction, threatIntel) {
    const { parsed, metrics } = extraction;

    this.featureMatrixGrid.innerHTML = `
      <div class="feature-pill-card">
        <div class="feature-pill-name">Protocol</div>
        <div class="feature-pill-value">${parsed.protocol.toUpperCase() || 'HTTP'}</div>
      </div>
      <div class="feature-pill-card">
        <div class="feature-pill-name">Hostname / Host</div>
        <div class="feature-pill-value">${parsed.hostname}</div>
      </div>
      <div class="feature-pill-card">
        <div class="feature-pill-name">Total Length</div>
        <div class="feature-pill-value">${metrics.urlLength} characters</div>
      </div>
      <div class="feature-pill-card">
        <div class="feature-pill-name">Subdomain Depth</div>
        <div class="feature-pill-value">${metrics.subdomainCount} subdomains</div>
      </div>
      <div class="feature-pill-card">
        <div class="feature-pill-name">Shannon Entropy</div>
        <div class="feature-pill-value">${metrics.hostnameEntropy} bits/char</div>
      </div>
      <div class="feature-pill-card">
        <div class="feature-pill-name">Top-Level Domain (.TLD)</div>
        <div class="feature-pill-value">.${metrics.tld || 'none'}</div>
      </div>
    `;

    // External Threat Intel (Requirement 8 - Decoupled)
    if (threatIntel) {
      this.threatIntelStatus.textContent = threatIntel.statusText;
      this.threatIntelFeedList.innerHTML = threatIntel.providersChecked.map(p => `
        <span class="threat-feed-tag">${p.name}: <strong style="color: ${p.status === 'Clean' ? '#10b981' : '#f59e0b'}">${p.status}</strong></span>
      `).join('');
    }
  }

  /**
   * Open the safety confirmation modal
   */
  openSafetyModal({ title, bodyText, url, confirmText, confirmClass, onConfirm }) {
    this.modalTitle.textContent = title;
    this.modalBodyText.textContent = bodyText;
    this.modalUrlDisplay.textContent = url;
    this.btnModalConfirm.textContent = confirmText;
    this.btnModalConfirm.className = `btn-modal-confirm ${confirmClass || ''}`;

    this.modalConfirmCallback = onConfirm;
    this.btnModalConfirm.onclick = () => {
      this.closeSafetyModal();
      if (this.modalConfirmCallback) this.modalConfirmCallback();
    };

    this.safetyModalBackdrop.classList.add('active');
  }

  closeSafetyModal() {
    this.safetyModalBackdrop.classList.remove('active');
  }

  /**
   * Opens URL strictly in a new tab with noopener, noreferrer after explicit confirmation
   */
  safeNavigate(rawUrl) {
    let target = rawUrl;
    if (!/^https?:\/\//i.test(target)) {
      target = `http://${target}`;
    }
    const win = window.open(target, '_blank', 'noopener,noreferrer');
    if (win) {
      win.opener = null;
    }
  }

  /**
   * Copy Safety Report to clipboard
   */
  copyReportToClipboard() {
    if (!this.currentScanData) return;
    const { extraction, prediction } = this.currentScanData;
    const reportText = `[PhishGuard AI URL Safety Assessment Report]
Target URL: ${extraction.rawUrl}
Assessment: ${prediction.status.title}
Risk Score: ${prediction.riskScore}/100 (Risk Level: ${prediction.riskLevel.toUpperCase()})
Model Confidence: ${prediction.modelConfidence}%
Identified Indicators:
${prediction.triggers.map(t => `- ${t.label}`).join('\n')}

Safety Advisory: ${prediction.status.description}
Generated: ${new Date().toUTCString()}
Notice: Machine-learning predictions are probabilistic. No automated detector can guarantee 100% safety.`;

    navigator.clipboard.writeText(reportText).then(() => {
      this.showToast("Safety assessment report copied to clipboard!");
    }).catch(() => {
      this.showToast("Unable to copy to clipboard.");
    });
  }

  /**
   * Show Toast Alert
   */
  showToast(message) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    this.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }
}
