/**
 * PhishGuard AI - Machine Learning Prediction Model
 * Calibrated logistic scoring & probabilistic classification engine.
 * Computes risk score (0-100), model confidence, status category, and signal attributions.
 */

import { CONFIG } from './config.js';

export class MLModel {
  /**
   * Sigmoid activation function
   * @param {number} z 
   * @returns {number}
   */
  static sigmoid(z) {
    return 1 / (1 + Math.exp(-z));
  }

  /**
   * Evaluates feature vector and returns comprehensive machine learning prediction
   * @param {Object} extractionResult 
   * @returns {Object} Prediction details
   */
  static predict(extractionResult) {
    const { features, triggers, metrics } = extractionResult;
    const weights = CONFIG.MODEL_WEIGHTS;

    let rawScore = 0;
    const featureContributions = [];

    // Evaluate each weighted feature
    for (const [key, weight] of Object.entries(weights)) {
      if (features[key] === true) {
        rawScore += weight;
        featureContributions.push({
          feature: key,
          weight: weight
        });
      }
    }

    // Baseline reputation attenuation for verified top-level authoritative domains
    if (features.isKnownTrustedDomain && !features.hasAtSymbol && !features.hasPunycodeHomograph && !features.hasDoubleSlashRedirect && !features.isIpAddress) {
      rawScore = Math.max(0, rawScore * 0.15);
    }

    // Smooth logit scaling
    // Maps rawScore 0 -> ~5-10%, rawScore 25-45 -> ~35-65%, rawScore 55+ -> ~80-99%
    const normalizedLogit = (rawScore - 32) / 12;
    const probability = this.sigmoid(normalizedLogit);

    // Compute integer Risk Score from 0 to 100
    let riskScore = Math.round(probability * 100);

    // Boundary constraints based on triggers
    if (triggers.length === 0) {
      riskScore = Math.min(riskScore, 10); // Clean baseline
    } else if (features.isIpAddress || features.hasAtSymbol || features.hasPunycodeHomograph || (features.hasSuspiciousKeyword && features.isSuspiciousTld)) {
      riskScore = Math.max(riskScore, 78); // High severity attack vectors
    }

    // Ensure strictly within 0-100
    riskScore = Math.max(0, Math.min(100, riskScore));

    // Determine Classification & Status Category based on configurable thresholds
    let categoryKey;
    if (riskScore <= CONFIG.THRESHOLDS.LOW_MAX) {
      categoryKey = "LOW";
    } else if (riskScore <= CONFIG.THRESHOLDS.MEDIUM_MAX) {
      categoryKey = "MEDIUM";
    } else {
      categoryKey = "HIGH";
    }

    const statusDef = CONFIG.STATUS_DEFINITIONS[categoryKey];

    // Compute Model Confidence (Probabilistic certainty based on feature distance from decision boundary)
    // Avoid describing confidence as an absolute guarantee
    const distanceFromBoundary = Math.abs(probability - 0.5);
    let confidencePercent = Math.round(75 + (distanceFromBoundary * 44));
    confidencePercent = Math.min(98, Math.max(78, confidencePercent));

    return {
      riskScore,
      riskLevel: statusDef.riskLevel,
      categoryKey,
      status: statusDef,
      modelConfidence: confidencePercent,
      probability: Number(probability.toFixed(4)),
      triggers,
      featureContributions,
      timestamp: new Date().toISOString()
    };
  }
}
