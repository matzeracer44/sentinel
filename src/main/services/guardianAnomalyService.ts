import { getGuardianAnomalyConfig, updateGuardianAnomalyConfig } from '@main/services/telemetryStore';
import type { GuardianAnomalyConfig } from '@/shared/ipcSchemas';

export async function loadGuardianAnomalyConfig(): Promise<GuardianAnomalyConfig> {
  return getGuardianAnomalyConfig();
}

export async function saveGuardianAnomalyConfig(config: GuardianAnomalyConfig): Promise<GuardianAnomalyConfig> {
  const normalized: GuardianAnomalyConfig = {
    enabled: config.enabled,
    sensitivity: config.sensitivity ?? 'medium',
    windowMinutes: Math.min(Math.max(config.windowMinutes, 5), 24 * 60),
    minSamples: Math.min(Math.max(config.minSamples, 10), 10000),
  };
  return updateGuardianAnomalyConfig(normalized);
}
