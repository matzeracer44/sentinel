/**
 * Sentinel Unified — RadialLayout
 * SVG container that renders the D3 force-directed radial layout:
 * cluster rings, edges, nodes, and handles zoom/pan transforms.
 */

import React, { useRef, useCallback, useMemo } from 'react';
import type { ConnectorNode, ConnectorEdge, SimulationNode, ClusterType } from '../../types/connectorMap';
import { useD3Simulation } from './useD3Simulation';
import ClusterRing from './ClusterRing';
import ConnectorEdge_ from './ConnectorEdge';
import ConnectorNode_ from './ConnectorNode';

interface RadialLayoutProps {
  nodes: ConnectorNode[];
  edges: ConnectorEdge[];
  width: number;
  height: number;
  zoom: number;
  selectedNode: string | null;
  hoveredNode: string | null;
  onSelectNode: (id: string | null) => void;
  onHoverNode: (id: string | null) => void;
}

const RadialLayout: React.FC<RadialLayoutProps> = ({
  nodes,
  edges,
  width,
  height,
  zoom,
  selectedNode,
  hoveredNode,
  onSelectNode,
  onHoverNode,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);

  const { simulationNodes, tick, dragStart, dragMove, dragEnd } = useD3Simulation({
    nodes,
    edges,
    width,
    height,
  });

  // Build a lookup map for quick node resolution in edges
  const nodeMap = useMemo(() => {
    const map = new Map<string, SimulationNode>();
    for (const n of simulationNodes) {
      map.set(n.id, n);
    }
    return map;
  }, [simulationNodes, tick]);

  // Determine which cluster is "active" (hovered node's cluster)
  const activeCluster: ClusterType | null = useMemo(() => {
    if (hoveredNode) {
      const node = nodeMap.get(hoveredNode);
      if (node && node.ring !== 0) return node.cluster;
    }
    return null;
  }, [hoveredNode, nodeMap]);

  // Determine dimmed edges (edges not connected to hovered node)
  const hoveredNodeEdges = useMemo(() => {
    if (!hoveredNode) return null;
    return new Set(
      edges
        .filter((e) => e.source === hoveredNode || e.target === hoveredNode)
        .map((e) => `${e.source}-${e.target}`)
    );
  }, [hoveredNode, edges]);

  const handleBackgroundClick = useCallback(() => {
    onSelectNode(null);
  }, [onSelectNode]);

  const handleNodeClick = useCallback(
    (id: string) => {
      onSelectNode(id === selectedNode ? null : id);
    },
    [onSelectNode, selectedNode]
  );

  const handleMouseEnter = useCallback(
    (id: string) => {
      onHoverNode(id);
    },
    [onHoverNode]
  );

  const handleMouseLeave = useCallback(() => {
    onHoverNode(null);
  }, [onHoverNode]);

  const cx = width / 2;
  const cy = height / 2;

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${width} ${height}`}
      onClick={handleBackgroundClick}
      style={{ background: 'transparent' }}
    >
      <g transform={`translate(${cx * (1 - zoom)}, ${cy * (1 - zoom)}) scale(${zoom})`}>
        {/* Layer 1: Cluster rings and sector arcs */}
        <ClusterRing width={width} height={height} activeCluster={activeCluster} />

        {/* Layer 2: Edges */}
        <g className="edges-layer">
          {edges.map((edge) => {
            const sourceNode = nodeMap.get(edge.source);
            const targetNode = nodeMap.get(edge.target);
            if (!sourceNode || !targetNode) return null;

            const edgeKey = `${edge.source}-${edge.target}`;
            const dimmed = hoveredNodeEdges !== null && !hoveredNodeEdges.has(edgeKey);

            return (
              <ConnectorEdge_
                key={edgeKey}
                sourceNode={sourceNode}
                targetNode={targetNode}
                type={edge.type}
                animated={edge.animated}
                color={edge.color}
                label={edge.label}
                dimmed={dimmed}
              />
            );
          })}
        </g>

        {/* Layer 3: Nodes */}
        <g className="nodes-layer">
          {simulationNodes.map((node) => (
            <ConnectorNode_
              key={node.id}
              node={node}
              isSelected={selectedNode === node.id}
              isHovered={hoveredNode === node.id}
              onMouseEnter={handleMouseEnter}
              onMouseLeave={handleMouseLeave}
              onClick={handleNodeClick}
              onDragStart={dragStart}
              onDragMove={dragMove}
              onDragEnd={dragEnd}
            />
          ))}
        </g>
      </g>
    </svg>
  );
};

export default RadialLayout;
