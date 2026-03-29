/**
 * Security Utilities — Input Sanitization & Rate Limiting
 * Protects against XSS, injection, spam, and malicious URLs.
 */

const MAX_MESSAGE_LENGTH = 2000;

/**
 * Strip HTML tags and dangerous patterns from user input.
 */
export function sanitizeInput(text) {
  if (typeof text !== 'string') return '';
  let sanitized = text
    .replace(/<[^>]*>/g, '')
    .replace(/javascript\s*:/gi, '')
    .replace(/\bon\w+\s*=/gi, '')
    .replace(/data\s*:\s*text\/html/gi, '')
    .trim();
  if (sanitized.length > MAX_MESSAGE_LENGTH) {
    sanitized = sanitized.slice(0, MAX_MESSAGE_LENGTH);
  }
  return sanitized;
}

/**
 * Validate an email address with a strict regex.
 */
export function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return emailRegex.test(email) && email.length <= 254;
}

/**
 * Validate that a URL is safe (https only).
 */
export function sanitizeURL(url) {
  if (typeof url !== 'string' || !url.trim()) return '';
  const trimmed = url.trim();
  if (/^https:\/\//i.test(trimmed)) return trimmed;
  return '';
}

/**
 * Create a sliding-window rate limiter.
 */
export function createRateLimiter(maxActions = 20, windowMs = 30000) {
  const timestamps = [];
  return {
    check() {
      const now = Date.now();
      while (timestamps.length > 0 && timestamps[0] <= now - windowMs) {
        timestamps.shift();
      }
      if (timestamps.length >= maxActions) {
        const retryAfterMs = timestamps[0] + windowMs - now;
        return { allowed: false, retryAfterMs };
      }
      timestamps.push(now);
      return { allowed: true, retryAfterMs: 0 };
    },
    reset() {
      timestamps.length = 0;
    },
  };
}
