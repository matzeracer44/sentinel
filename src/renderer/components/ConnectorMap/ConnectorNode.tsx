/**
 * Sentinel Unified — ConnectorNode
 * SVG group rendering a single connector node with status LED,
 * cluster-colored border, label, and hover glow.
 */

import React, { useCallback } from 'react';
import type { SimulationNode, ClusterType } from '../../types/connectorMap';
import { CLUSTER_COLORS, NODE_RADIUS, NODE_FONT_SIZE } from './connectorMapTheme';
import StatusPulse from './StatusPulse';

interface ConnectorNodeProps {
  node: SimulationNode;
  isSelected: boolean;
  isHovered: boolean;
  onMouseEnter: (id: string) => void;
  onMouseLeave: () => void;
  onClick: (id: string) => void;
  onDragStart: (id: string, x: number, y: number) => void;
  onDragMove: (id: string, x: number, y: number) => void;
  onDragEnd: (id: string) => void;
}

const CLUSTER_SHORT: Record<ClusterType, string> = {
  core: 'CORE',
  firewall: 'FW',
  intel: 'INTEL',
  automation: 'AUTO',
  network: 'NET',
  dns: 'DNS',
  system: 'SYS',
  vault: 'VAULT',
};

const ConnectorNode: React.FC<ConnectorNodeProps> = React.memo(
  ({
    node,
    isSelected,
    isHovered,
    onMouseEnter,
    onMouseLeave,
    onClick,
    onDragStart,
    onDragMove,
    onDragEnd,
  }) => {
    const r = NODE_RADIUS[node.size];
    const fontSize = NODE_FONT_SIZE[node.size];
    const color = CLUSTER_COLORS[node.cluster];
    const isCore = node.ring === 0;

    const handleMouseDown = useCallback(
      (e: React.MouseEvent<SVGGElement>) => {
        if (isCore) return;
        e.preventDefault();
        e.stopPropagation();

        const svg = (e.target as SVGElement).ownerSVGElement;
        if (!svg) return;

        const pt = svg.createSVGPoint();
        pt.x = e.clientX;
        pt.y = e.clientY;
        const svgPt = pt.matrixTransform(svg.getScreenCTM()?.inverse());

        onDragStart(node.id, svgPt.x, svgPt.y);

        const handleMove = (me: MouseEvent) => {
          const mp = svg.createSVGPoint();
          mp.x = me.clientX;
          mp.y = me.clientY;
          const mvPt = mp.matrixTransform(svg.getScreenCTM()?.inverse());
          onDragMove(node.id, mvPt.x, mvPt.y);
        };

        const handleUp = () => {
          window.removeEventListener('mousemove', handleMove);
          window.removeEventListener('mouseup', handleUp);
          onDragEnd(node.id);
        };

        window.addEventListener('mousemove', handleMove);
        window.addEventListener('mouseup', handleUp);
      },
      [node.id, isCore, onDragStart, onDragMove, onDragEnd]
    );

    const handleClick = useCallback(
      (e: React.MouseEvent) => {
        e.stopPropagation();
        onClick(node.id);
      },
      [node.id, onClick]
    );

    const handleEnter = useCallback(() => onMouseEnter(node.id), [node.id, onMouseEnter]);

    if (isCore) {
      return (
        <g
          className="connector-node core-node"
          transform={`translate(${node.x}, ${node.y})`}
          onClick={handleClick}
          onMouseEnter={handleEnter}
          onMouseLeave={onMouseLeave}
        >
          <circle className="node-bg" r={36} />
          <StatusPulse status={node.status} cx={0} cy={-28} radius={4} />
          <text className="core-label" dy={5}>
            SENTINEL
          </text>
        </g>
      );
    }

    return (
      <g
        className="connector-node"
        transform={`translate(${node.x}, ${node.y})`}
        onMouseDown={handleMouseDown}
        onClick={handleClick}
        onMouseEnter={handleEnter}
        onMouseLeave={onMouseLeave}
      >
        {/* Hover glow */}
        <circle
          className="node-hover-glow"
          r={r + 10}
          fill={color}
          style={{ filter: `blur(8px)` }}
        />

        {/* Selection ring */}
        {isSelected && (
          <circle
            className="node-selection-ring"
            r={r + 5}
            stroke={color}
          />
        )}

        {/* Background circle */}
        <circle
          className="node-bg"
          r={r}
          stroke={color}
          style={{
            strokeOpacity: isHovered ? 0.9 : 0.5,
          }}
        />

        {/* Status LED */}
        <StatusPulse
          status={node.status}
          cx={r * 0.65}
          cy={-r * 0.65}
          radius={node.size === 'sm' ? 2 : 3}
        />

        {/* Node name */}
        <text
          className="node-label"
          dy={node.size === 'lg' ? 1 : 0.5}
          fontSize={fontSize}
        >
          {node.name}
        </text>

        {/* Cluster tag */}
        <text
          className="node-cluster-tag"
          dy={r - 3}
          fill={color}
        >
          {CLUSTER_SHORT[node.cluster]}
        </text>

        {/* ARGUS badge */}
        {node.source === 'argus' && (
          <text
            className="node-source-badge"
            dy={-r + 5}
            fill="#ffaa00"
          >
            A
          </text>
        )}
      </g>
    );
  }
);

ConnectorNode.displayName = 'ConnectorNode';

export default ConnectorNode;
