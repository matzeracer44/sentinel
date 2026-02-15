/**
 * Sentinel Unified — ConnectorEdge
 * SVG path rendering a connection between two nodes,
 * with optional animated particle flow along the edge.
 */

import React, { useMemo } from 'react';
import type { SimulationNode, EdgeType } from '../../types/connectorMap';
import { EDGE_COLORS, CLUSTER_COLORS } from './connectorMapTheme';

interface ConnectorEdgeProps {
  sourceNode: SimulationNode;
  targetNode: SimulationNode;
  type: EdgeType;
  animated: boolean;
  color?: string;
  label?: string;
  dimmed: boolean;
}

const EDGE_TYPE_CLASS: Record<EdgeType, string> = {
  'data-flow': 'connector-edge--data-flow',
  trigger: 'connector-edge--trigger',
  dependency: 'connector-edge--dependency',
  heartbeat: 'connector-edge--heartbeat',
};

function resolveEdgeColor(type: EdgeType, customColor?: string, sourceCluster?: string): string {
  if (customColor) return customColor;
  switch (type) {
    case 'data-flow':
      return EDGE_COLORS.dataFlow;
    case 'trigger':
      return EDGE_COLORS.trigger;
    case 'heartbeat':
      return EDGE_COLORS.heartbeat;
    case 'dependency':
      return EDGE_COLORS.active;
    default:
      return EDGE_COLORS.active;
  }
}

function buildCurvedPath(
  sx: number,
  sy: number,
  tx: number,
  ty: number
): string {
  const dx = tx - sx;
  const dy = ty - sy;
  const dist = Math.sqrt(dx * dx + dy * dy);

  if (dist < 50) {
    return `M ${sx} ${sy} L ${tx} ${ty}`;
  }

  const midX = (sx + tx) / 2;
  const midY = (sy + ty) / 2;
  const curvature = Math.min(dist * 0.15, 40);
  const nx = -dy / dist;
  const ny = dx / dist;
  const cx = midX + nx * curvature;
  const cy = midY + ny * curvature;

  return `M ${sx} ${sy} Q ${cx} ${cy} ${tx} ${ty}`;
}

const PARTICLE_COUNT = 3;
const PARTICLE_RADIUS = 1.8;

const ConnectorEdge: React.FC<ConnectorEdgeProps> = React.memo(
  ({ sourceNode, targetNode, type, animated, color, label, dimmed }) => {
    const pathD = useMemo(
      () =>
        buildCurvedPath(
          sourceNode.x,
          sourceNode.y,
          targetNode.x,
          targetNode.y
        ),
      [sourceNode.x, sourceNode.y, targetNode.x, targetNode.y]
    );

    const edgeColor = resolveEdgeColor(type, color, sourceNode.cluster);
    const pathId = useMemo(
      () => `edge-${sourceNode.id}-${targetNode.id}`.replace(/\./g, '_'),
      [sourceNode.id, targetNode.id]
    );

    const particles = useMemo(() => {
      if (!animated) return null;
      return Array.from({ length: PARTICLE_COUNT }, (_, i) => {
        const delay = (i / PARTICLE_COUNT) * 4;
        return (
          <circle
            key={i}
            className="edge-particle"
            r={PARTICLE_RADIUS}
            fill={edgeColor}
            opacity={0}
          >
            <animateMotion
              dur="4s"
              repeatCount="indefinite"
              begin={`${delay}s`}
            >
              <mpath href={`#${pathId}`} />
            </animateMotion>
            <animate
              attributeName="opacity"
              values="0;0.9;0.9;0"
              keyTimes="0;0.1;0.85;1"
              dur="4s"
              repeatCount="indefinite"
              begin={`${delay}s`}
            />
          </circle>
        );
      });
    }, [animated, pathId, edgeColor]);

    return (
      <g style={{ opacity: dimmed ? 0.08 : 1, transition: 'opacity 300ms ease' }}>
        <path
          id={pathId}
          className={`connector-edge ${EDGE_TYPE_CLASS[type]}`}
          d={pathD}
          stroke={edgeColor}
        />
        {particles}
      </g>
    );
  }
);

ConnectorEdge.displayName = 'ConnectorEdge';

export default ConnectorEdge;
