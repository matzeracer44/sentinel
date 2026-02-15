import { inspectTLS, TLSInspectionSummary } from './tlsInspector';

export type TLSWorkerStatus = 'pending' | 'ready' | 'error';

export interface TLSPenaltyResult {
  host: string;
  penalty: number;
  reason?: string;
}

const TLS_PENALTY_EXPIRED = 25;
const TLS_PENALTY_SELF_SIGNED = 25;
const TLS_PENALTY_WEAK_PROTOCOL = 15;

const tlsListeners = new Set<(result: TLSPenaltyResult) => void>();

const statusMap = new Map<string, TLSWorkerStatus>();
const summaryMap = new Map<string, TLSInspectionSummary>();
const queue: string[] = [];
let processing = false;

export function requestTLSInspection(host: string): void {
  const normalized = host?.trim().toLowerCase();
  if (!normalized) return;
  if (!statusMap.has(normalized)) {
    statusMap.set(normalized, 'pending');
    queue.push(normalized);
    processQueue();
  }
}

export function getTLSStatus(host: string): TLSWorkerStatus {
  return statusMap.get(host?.trim().toLowerCase() || '') ?? 'pending';
}

export function getTLSSummary(host: string): TLSInspectionSummary | undefined {
  return summaryMap.get(host?.trim().toLowerCase() || '');
}

function calculateTLSPenalty(summary: TLSInspectionSummary): TLSPenaltyResult {
  let penalty = 0;
  const reasons: string[] = [];

  if (summary.issues) {
    const issuesLower = summary.issues.map((i) => i.toLowerCase());
    if (issuesLower.some((i) => i.includes('expired'))) {
      penalty += TLS_PENALTY_EXPIRED;
      reasons.push('expired certificate');
    }
    if (issuesLower.some((i) => i.includes('self-signed') || i.includes('selfsigned'))) {
      penalty += TLS_PENALTY_SELF_SIGNED;
      reasons.push('self-signed certificate');
    }
    if (issuesLower.some((i) => i.includes('weak') || i.includes('ssl3') || i.includes('tls1.0'))) {
      penalty += TLS_PENALTY_WEAK_PROTOCOL;
      reasons.push('weak protocol');
    }
  }

  if (summary.grade) {
    const grade = summary.grade.toUpperCase();
    if (grade === 'F' || grade === 'T') {
      penalty += 20;
      reasons.push(`grade ${grade}`);
    } else if (grade.startsWith('C') || grade.startsWith('D')) {
      penalty += 10;
      reasons.push(`grade ${grade}`);
    }
  }

  return {
    host: summary.host,
    penalty: Math.min(penalty, 50),
    reason: reasons.length ? reasons.join(', ') : undefined,
  };
}

function notifyListeners(result: TLSPenaltyResult): void {
  tlsListeners.forEach((listener) => {
    try {
      listener(result);
    } catch (err) {
      console.error('[TLSWorker] Listener error:', err);
    }
  });
}

function processQueue(): void {
  if (processing) return;
  const next = queue.shift();
  if (!next) return;
  processing = true;
  inspectTLS(next)
    .then((summary) => {
      summaryMap.set(next, summary);
      statusMap.set(next, 'ready');
      const penaltyResult = calculateTLSPenalty(summary);
      if (penaltyResult.penalty > 0) {
        notifyListeners(penaltyResult);
      }
    })
    .catch((error) => {
      console.warn('[TLSWorker] TLS inspection failed for', next, error);
      statusMap.set(next, 'error');
    })
    .finally(() => {
      processing = false;
      if (queue.length) {
        processQueue();
      }
    });
}

export function subscribeTLSPenalties(listener: (result: TLSPenaltyResult) => void): () => void {
  tlsListeners.add(listener);
  return () => tlsListeners.delete(listener);
}

export function getTLSPenaltyForHost(host: string): number {
  const summary = summaryMap.get(host?.trim().toLowerCase() || '');
  if (!summary) return 0;
  return calculateTLSPenalty(summary).penalty;
}
