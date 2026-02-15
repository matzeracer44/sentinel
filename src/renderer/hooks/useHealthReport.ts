import { useQuery, type UseQueryResult } from '@tanstack/react-query';

export type HealthStatus = 'pass' | 'warn' | 'fail';

export interface HealthCheckEntry {
  component: string;
  status: HealthStatus;
  durationMs: number;
  details?: string;
  error?: string;
  meta?: Record<string, unknown>;
}

export interface HealthReportSummary {
  generatedAt: number;
  cached: boolean;
  totalDurationMs: number;
  healthy: boolean;
  failing: number;
  warning: number;
}

export interface HealthReport {
  summary: HealthReportSummary;
  checks: {
    sqlite: HealthCheckEntry;
    telemetry: HealthCheckEntry;
    firewallHistory: HealthCheckEntry;
    connectivity: HealthCheckEntry;
  };
}

async function fetchHealthReport(): Promise<HealthReport> {
  const response = await window.electronAPI.getHealthReport();
  if (!response || response.success !== true || !response.data) {
    const errorMessage = response && 'error' in response && response.error
      ? response.error
      : 'Health report unavailable';
    throw new Error(errorMessage);
  }
  return response.data as HealthReport;
}

export function useHealthReport(intervalMs = 15_000): UseQueryResult<HealthReport> {
  return useQuery<HealthReport>({
    queryKey: ['sentinel-health-report'],
    queryFn: fetchHealthReport,
    refetchInterval: intervalMs,
    refetchOnWindowFocus: false,
    retry: 1,
  });
}
