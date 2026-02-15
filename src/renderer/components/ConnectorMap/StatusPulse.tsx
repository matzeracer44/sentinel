/**
 * Sentinel Unified — StatusPulse
 * Animated SVG status LED with glow ring for connector nodes.
 */

import React from 'react';
import type { NodeStatus } from '../../types/connectorMap';

interface StatusPulseProps {
  status: NodeStatus;
  cx: number;
  cy: number;
  radius?: number;
}

const STATUS_CLASS: Record<NodeStatus, string> = {
  online: 'status-led--online',
  degraded: 'status-led--degraded',
  error: 'status-led--error',
  offline: 'status-led--offline',
};

const GLOW_CLASS: Record<NodeStatus, string> = {
  online: 'status-glow--online',
  degraded: 'status-glow--degraded',
  error: 'status-glow--error',
  offline: 'status-glow--offline',
};

const StatusPulse: React.FC<StatusPulseProps> = React.memo(
  ({ status, cx, cy, radius = 3 }) => {
    return (
      <g className="status-led">
        <circle
          className={`status-glow ${GLOW_CLASS[status]}`}
          cx={cx}
          cy={cy}
          r={radius + 4}
        />
        <circle
          className={STATUS_CLASS[status]}
          cx={cx}
          cy={cy}
          r={radius}
        />
      </g>
    );
  }
);

StatusPulse.displayName = 'StatusPulse';

export default StatusPulse;
