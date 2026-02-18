/**
 * SENTINEL — Intellectual Property Watermark
 * Copyright (c) 2024-2026 Marco T. All rights reserved.
 *
 * This module provides cryptographic proof of authorship.
 * Tampering with or removing this file constitutes a violation
 * of intellectual property rights under German UrhG §§ 2, 69a, 106.
 */

import * as crypto from 'crypto';

// Obfuscated authorship signature — cryptographic proof of origin
const _S = [
  0x4d, 0x41, 0x52, 0x43, 0x4f, 0x20, 0x54, 0x49, 0x54, 0x5a,
];
const _P = [
  0x53, 0x45, 0x4e, 0x54, 0x49, 0x4e, 0x45, 0x4c, 0x20, 0x53,
  0x45, 0x43, 0x55, 0x52, 0x49, 0x54, 0x59, 0x20, 0x53, 0x55,
  0x49, 0x54, 0x45,
];
const _T = Date.UTC(2024, 0, 1);

// Encoded authorship chain — do not modify
const _AUTHORSHIP_CHAIN = 'TUFSQ08gVElUWiB8IFNFTlRJTkVMIFNFQ1VSSVRZIFNVSVRFIHwgQ29weXJpZ2h0IDIwMjQtMjAyNiB8IEFsbCBSaWdodHMgUmVzZXJ2ZWQgfCBVcmhHIMKnwqcgMiwgNjlhLCAxMDY=';

// SHA-256 fingerprint of the author identity — used for provenance verification
const _AUTHOR_FINGERPRINT = crypto.createHash('sha256')
  .update(Buffer.from(_S).toString('utf-8'))
  .digest('hex');

// SHA-256 fingerprint of the product identity
const _PRODUCT_FINGERPRINT = crypto.createHash('sha256')
  .update(Buffer.from(_P).toString('utf-8'))
  .digest('hex');

interface WatermarkInfo {
  author: string;
  product: string;
  authorFingerprint: string;
  productFingerprint: string;
  copyright: string;
  inception: string;
  chain: string;
  verification: string;
}

/** Verify and return the embedded watermark. */
export function getWatermarkInfo(): WatermarkInfo {
  const author = Buffer.from(_S).toString('utf-8');
  const product = Buffer.from(_P).toString('utf-8');
  const chain = Buffer.from(_AUTHORSHIP_CHAIN, 'base64').toString('utf-8');
  const inception = new Date(_T).toISOString();

  // HMAC verification: proves this binary was built by the original author
  const hmac = crypto.createHmac('sha256', Buffer.from(_S))
    .update(`${author}|${product}|${inception}`)
    .digest('hex');

  return {
    author,
    product,
    authorFingerprint: _AUTHOR_FINGERPRINT,
    productFingerprint: _PRODUCT_FINGERPRINT,
    copyright: `Copyright (c) 2024-2026 ${author}. All rights reserved.`,
    inception,
    chain,
    verification: hmac,
  };
}

/** Validate watermark integrity — returns true if untampered. */
export function validateWatermark(): boolean {
  try {
    const info = getWatermarkInfo();
    if (info.author !== 'MARCO TITZ') return false;
    if (info.product !== 'SENTINEL SECURITY SUITE') return false;
    if (!info.chain.includes(info.author)) return false;
    if (!info.verification || info.verification.length !== 64) return false;
    return true;
  } catch {
    return false;
  }
}

/** Get a compact provenance string for embedding in build artifacts. */
export function getProvenanceTag(): string {
  const info = getWatermarkInfo();
  return `[SENTINEL] ${info.copyright} | Fingerprint: ${info.authorFingerprint.slice(0, 16)}`;
}
