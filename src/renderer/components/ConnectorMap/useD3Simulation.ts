/**
 * Sentinel Unified — D3 Radial Force Simulation Hook
 *
 * Manages a D3 force simulation that positions ConnectorNodes
 * in concentric rings with cluster-based angular sectors.
 */

import { useRef, useEffect, useCallback, useState } from 'react';
import * as d3 from 'd3';
import type { ConnectorNode, SimulationNode, ConnectorEdge, RingIndex, ClusterType } from '../../types/connectorMap';
import { ringRadius, CLUSTER_SECTORS, NODE_RADIUS } from './connectorMapTheme';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function degreesToRadians(deg: number): number {
  return (deg * Math.PI) / 180;
}

function clusterAngleCenter(cluster: ClusterType): number {
  const sector = CLUSTER_SECTORS.find((s) => s.cluster === cluster);
  if (!sector) return 0;
  return degreesToRadians((sector.angleStart + sector.angleEnd) / 2 - 90);
}

function clusterAngleSpread(cluster: ClusterType): number {
  const sector = CLUSTER_SECTORS.find((s) => s.cluster === cluster);
  if (!sector) return Math.PI * 2;
  return degreesToRadians(sector.angleEnd - sector.angleStart);
}

function initializeNodePositions(
  nodes: ConnectorNode[],
  centerX: number,
  centerY: number,
  viewportSize: number
): SimulationNode[] {
  return nodes.map((node, i) => {
    if (node.ring === 0) {
      return { ...node, x: centerX, y: centerY, vx: 0, vy: 0 };
    }

    const r = ringRadius(node.ring, viewportSize);
    const angleCtr = clusterAngleCenter(node.cluster);
    const spread = clusterAngleSpread(node.cluster);

    const clusterNodes = nodes.filter(
      (n) => n.cluster === node.cluster && n.ring === node.ring
    );
    const indexInCluster = clusterNodes.indexOf(node);
    const countInCluster = clusterNodes.length;

    const fraction =
      countInCluster <= 1
        ? 0
        : (indexInCluster / (countInCluster - 1)) - 0.5;

    const angle = angleCtr + fraction * spread * 0.85;

    return {
      ...node,
      x: centerX + r * Math.cos(angle),
      y: centerY + r * Math.sin(angle),
      vx: 0,
      vy: 0,
    };
  });
}

// ---------------------------------------------------------------------------
// Custom Cluster Force
// ---------------------------------------------------------------------------

function forceCluster(
  centerX: number,
  centerY: number,
  viewportSize: number,
  strength: number = 0.3
) {
  let nodes: SimulationNode[] = [];

  function force(alpha: number) {
    for (const node of nodes) {
      if (node.ring === 0) continue;

      const targetR = ringRadius(node.ring, viewportSize);
      const angleCtr = clusterAngleCenter(node.cluster);

      const targetX = centerX + targetR * Math.cos(angleCtr);
      const targetY = centerY + targetR * Math.sin(angleCtr);

      node.vx += (targetX - node.x) * strength * alpha;
      node.vy += (targetY - node.y) * strength * alpha;
    }
  }

  force.initialize = (n: SimulationNode[]) => {
    nodes = n;
  };

  return force;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface UseD3SimulationOptions {
  nodes: ConnectorNode[];
  edges: ConnectorEdge[];
  width: number;
  height: number;
}

export interface UseD3SimulationResult {
  simulationNodes: SimulationNode[];
  tick: number;
  reheat: () => void;
  dragStart: (nodeId: string, x: number, y: number) => void;
  dragMove: (nodeId: string, x: number, y: number) => void;
  dragEnd: (nodeId: string) => void;
}

export function useD3Simulation({
  nodes,
  edges,
  width,
  height,
}: UseD3SimulationOptions): UseD3SimulationResult {
  const simulationRef = useRef<d3.Simulation<SimulationNode, undefined> | null>(null);
  const nodesRef = useRef<SimulationNode[]>([]);
  const [tick, setTick] = useState(0);

  const centerX = width / 2;
  const centerY = height / 2;
  const viewportSize = Math.min(width, height);

  useEffect(() => {
    if (width === 0 || height === 0) return;

    const simNodes = initializeNodePositions(nodes, centerX, centerY, viewportSize);
    nodesRef.current = simNodes;

    const simulation = d3
      .forceSimulation<SimulationNode>(simNodes)
      .force(
        'radial',
        d3
          .forceRadial<SimulationNode>(
            (d) => (d.ring === 0 ? 0 : ringRadius(d.ring, viewportSize)),
            centerX,
            centerY
          )
          .strength(0.8)
      )
      .force(
        'collision',
        d3
          .forceCollide<SimulationNode>()
          .radius((d) => NODE_RADIUS[d.size] + 6)
          .strength(0.7)
          .iterations(2)
      )
      .force('cluster', forceCluster(centerX, centerY, viewportSize, 0.15) as any)
      .force(
        'charge',
        d3.forceManyBody<SimulationNode>().strength(-25).distanceMax(200)
      )
      .alphaDecay(0.025)
      .velocityDecay(0.35)
      .on('tick', () => {
        setTick((t) => t + 1);
      });

    // Pin core node to center
    const coreNode = simNodes.find((n) => n.ring === 0);
    if (coreNode) {
      coreNode.fx = centerX;
      coreNode.fy = centerY;
    }

    simulationRef.current = simulation;

    return () => {
      simulation.stop();
      simulationRef.current = null;
    };
  }, [nodes, edges, width, height, centerX, centerY, viewportSize]);

  const reheat = useCallback(() => {
    simulationRef.current?.alpha(0.5).restart();
  }, []);

  const dragStart = useCallback(
    (nodeId: string, x: number, y: number) => {
      const sim = simulationRef.current;
      if (!sim) return;
      sim.alphaTarget(0.3).restart();
      const node = nodesRef.current.find((n) => n.id === nodeId);
      if (node) {
        node.fx = x;
        node.fy = y;
      }
    },
    []
  );

  const dragMove = useCallback(
    (nodeId: string, x: number, y: number) => {
      const node = nodesRef.current.find((n) => n.id === nodeId);
      if (node) {
        node.fx = x;
        node.fy = y;
      }
    },
    []
  );

  const dragEnd = useCallback(
    (nodeId: string) => {
      const sim = simulationRef.current;
      if (!sim) return;
      sim.alphaTarget(0);
      const node = nodesRef.current.find((n) => n.id === nodeId);
      if (node && node.ring !== 0) {
        node.fx = null;
        node.fy = null;
      }
    },
    []
  );

  return {
    simulationNodes: nodesRef.current,
    tick,
    reheat,
    dragStart,
    dragMove,
    dragEnd,
  };
}
