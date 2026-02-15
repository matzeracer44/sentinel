/**
 * SENTINEL UNIFIED — Automation Types (Renderer)
 */

export interface QuickActionResult {
  success: boolean;
  message: string;
  actions?: string[];
}

export interface AutonomousModeConfig {
  enabled: boolean;
}
