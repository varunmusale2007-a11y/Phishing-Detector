/**
 * PhishGuard AI - Application Coordinator
 * Connects FeatureExtractor, MLModel, ThreatIntelService, and UIController.
 */

import { FeatureExtractor } from './featureExtractor.js';
import { MLModel } from './mlModel.js';
import { threatIntelService } from './threatIntel.js';
import { UIController } from './ui.js';

class App {
  constructor() {
    this.ui = new UIController();
    this.init();
  }

  init() {
    // Render Quick Test Vectors / Samples
    this.ui.renderSamplePills((selectedUrl) => {
      this.executeScan(selectedUrl);
    });

    // Bind URL form submission
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
      scanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const rawUrl = this.ui.urlInput.value.trim();
        if (!rawUrl) {
          this.ui.showToast("Please enter a URL to scan.");
          this.ui.urlInput.focus();
          return;
        }
        this.executeScan(rawUrl);
      });
    }

    // Auto-focus input on launch
    if (this.ui.urlInput) {
      this.ui.urlInput.focus();
    }
  }

  /**
   * Main scan workflow:
   * 1. Extract URL Features (Lexical, Structural, Entropy)
   * 2. ML Probability & Risk Scoring (Python backend or Client-side engine)
   * 3. Threat Intelligence telemetry
   * 4. Synthesize and render final Prominent Result Card
   */
  async executeScan(rawUrl) {
    try {
      // Step 1: Feature Extraction
      this.ui.updateScanProgress(0);
      await this.delay(180);

      let scanResult = null;

      // Attempt to query Python backend API if running
      try {
        const response = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: rawUrl })
        });

        if (response.ok) {
          const apiData = await response.json();
          if (apiData.success) {
            scanResult = {
              extraction: apiData.extraction,
              prediction: apiData.prediction,
              threatIntel: apiData.threatIntel
            };
          }
        }
      } catch (networkErr) {
        // Backend offline or running in pure static/GitHub Pages mode -> use client-side ML
      }

      // Step 2: Client-side ML fallback if backend was not used
      if (!scanResult) {
        this.ui.updateScanProgress(1);
        await this.delay(200);

        const extraction = FeatureExtractor.extractFeatures(rawUrl);
        const prediction = MLModel.predict(extraction);

        this.ui.updateScanProgress(2);
        const threatIntel = await threatIntelService.queryIntelligence(rawUrl, extraction.parsed);

        scanResult = {
          extraction,
          prediction,
          threatIntel
        };
      } else {
        this.ui.updateScanProgress(2);
        await this.delay(150);
      }

      // Step 4: Finalizing
      this.ui.updateScanProgress(3);
      await this.delay(150);

      this.ui.hideScanProgress();

      // Render prominent result
      this.ui.renderResult(scanResult);

      // Save to recent scans in localStorage
      this.saveToHistory(rawUrl, scanResult.prediction);

    } catch (err) {
      this.ui.hideScanProgress();
      this.ui.showToast(err.message || "An error occurred while analyzing the URL.");
      console.error("[PhishGuard Error]", err);
    }
  }

  saveToHistory(url, prediction) {
    try {
      const history = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
      const entry = {
        url,
        category: prediction.categoryKey,
        riskScore: prediction.riskScore,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      // Keep last 10
      const updated = [entry, ...history.filter(h => h.url !== url)].slice(0, 10);
      localStorage.setItem('phishguard_history', JSON.stringify(updated));
    } catch (e) {
      // Ignore localStorage errors
    }
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Initialize Application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.phishGuardApp = new App();
});
