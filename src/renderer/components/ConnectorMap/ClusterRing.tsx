/**
 * Sentinel Unified — ClusterRing
 * Renders concentric ring circles with sector arcs and labels.
 */

import React, { useMemo } from 'react';
import type { RingIndex, ClusterType } from '../../types/connectorMap';
import { RING_CONFIGS, CLUSTER_SECTORS, CLUSTER_COLORS, ringRadius } from './connectorMapTheme';

interface ClusterRingProps {
  width: number;
  height: number;
  activeCluster?: ClusterType | null;
}

function degreesToRadians(deg: number): number {
  return (deg * Math.PI) / 180;
}

function describeArc(
  cx: number,
  cy: number,
  radius: number,
  startAngle: number,
  endAngle: number
): string {
  const startRad = degreesToRadians(startAngle - 90);
  const endRad = degreesToRadians(endAngle - 90);

  const x1 = cx + radius * Math.cos(startRad);
  const y1 = cy + radius * Math.sin(startRad);
  const x2 = cx + radius * Math.cos(endRad);
  const y2 = cy + radius * Math.sin(endRad);

  const largeArc = endAngle - startAngle > 180 ? 1 : 0;

  return `M ${cx} ${cy} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} Z`;
}

const ClusterRing: React.FC<ClusterRingProps> = React.memo(
  ({ width, height, activeCluster }) => {
    const cx = width / 2;
    const cy = height / 2;
    const viewportSize = Math.min(width, height);

    const rings = useMemo(() => {
      return RING_CONFIGS.filter((rc) => rc.ring > 0).map((rc) => {
        const r = ringRadius(rc.ring as RingIndex, viewportSize);
        return { ...rc, radius: r };
      });
    }, [viewportSize]);

    const sectors = useMemo(() => {
      return CLUSTER_SECTORS.map((sector) => {
        const innerR = ringRadius(sector.ring as RingIndex, viewportSize) * 0.7;
        const outerR = ringRadius(sector.ring as RingIndex, viewportSize) * 1.3;
        const midAngle = degreesToRadians(
          (sector.angleStart + sector.angleEnd) / 2 - 90
        );
        const labelR = ringRadius(sector.ring as RingIndex, viewportSize) * 1.18;
        const labelX = cx + labelR * Math.cos(midAngle);
        const labelY = cy + labelR * Math.sin(midAngle);

        return {
          ...sector,
          innerR,
          outerR,
          labelX,
          labelY,
          midAngleDeg: (sector.angleStart + sector.angleEnd) / 2,
        };
      });
    }, [cx, cy, viewportSize]);

    return (
      <g className="cluster-rings">
        {/* Sector background arcs */}
        {sectors.map((sector) => {
          const isActive = !activeCluster || activeCluster === sector.cluster;
          return (
            <path
              key={`sector-${sector.cluster}`}
              className="sector-arc"
              d={describeArc(
                cx,
                cy,
                sector.outerR,
                sector.angleStart,
                sector.angleEnd
              )}
              fill={CLUSTER_COLORS[sector.cluster]}
              style={{
                opacity: isActive ? 0.05 : 0.015,
                transition: 'opacity 400ms ease',
              }}
            />
          );
        })}

        {/* Ring circles */}
        {rings.map((ring) => (
          <circle
            key={`ring-${ring.ring}`}
            className="ring-circle"
            cx={cx}
            cy={cy}
            r={ring.radius}
          />
        ))}

        {/* Ring labels (top of each ring) */}
        {rings.map((ring) => (
          <text
            key={`ring-label-${ring.ring}`}
            className="ring-label"
            x={cx}
            y={cy - ring.radius - 8}
            textAnchor="middle"
          >
            {ring.label}
          </text>
        ))}

        {/* Sector labels */}
        {sectors.map((sector) => {
          const isActive = !activeCluster || activeCluster === sector.cluster;
          return (
            <text
              key={`sector-label-${sector.cluster}`}
              x={sector.labelX}
              y={sector.labelY}
              textAnchor="middle"
              dominantBaseline="central"
              fill={CLUSTER_COLORS[sector.cluster]}
              fontSize={9}
              fontWeight={600}
              fontFamily="'Segoe UI', system-ui, sans-serif"
              letterSpacing="0.8px"
              style={{
                textTransform: 'uppercase' as const,
                opacity: isActive ? 0.7 : 0.2,
                transition: 'opacity 400ms ease',
                pointerEvents: 'none' as const,
              }}
            >
              {sector.label}
            </text>
          );
        })}
      </g>
    );
  }
);

ClusterRing.displayName = 'ClusterRing';

export default ClusterRing;
