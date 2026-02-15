/**
 * Sentinel Unified — ConnectorMap
 * Default view: Cluster Cards grid with live metrics.
 * Click a card to drill-down into that cluster's nodes (radial layout).
 * Back button returns to cards view.
 */

import React, { useCallback, useEffect, useRef, useState, useMemo } from 'react';
import type { ConnectorNode, ClusterType } from '../../types/connectorMap';
import { useConnectorData } from './useConnectorData';
import RadialLayout from './RadialLayout';
import MapControls from './MapControls';
import NodeModal from './NodeModal';
import { CLUSTER_COLORS, STATUS_COLORS } from './connectorMapTheme';
import './connectorMap.css';

const MIN_ZOOM = 0.3;
const MAX_ZOOM = 3;
const ZOOM_STEP = 0.15;

type ViewMode = 'cards' | 'radial' | 'drill';

const CLUSTER_META: { cluster: ClusterType; icon: string; label: string }[] = [
  { cluster: 'core', icon: '◆', label: 'SENTINEL CORE' },
  { cluster: 'firewall', icon: '\uD83D\uDD25', label: 'FIREWALL' },
  { cluster: 'intel', icon: '\uD83D\uDD0D', label: 'INTEL' },
  { cluster: 'network', icon: '\uD83D\uDCE1', label: 'NETWORK' },
  { cluster: 'automation', icon: '\u2699\uFE0F', label: 'AUTOMATION' },
  { cluster: 'dns', icon: '\uD83C\uDF10', label: 'DNS / GHOST' },
  { cluster: 'system', icon: '\uD83D\uDDA5\uFE0F', label: 'SYSTEM' },
  { cluster: 'vault', icon: '\uD83D\uDD12', label: 'VAULT' },
];

const ConnectorMap: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
  const [viewMode, setViewMode] = useState<ViewMode>('cards');
  const [drillCluster, setDrillCluster] = useState<ClusterType | null>(null);

  const {
    state,
    filteredNodes,
    filteredEdges,
    selectNode,
    hoverNode,
    toggleCluster,
    setZoom,
    resetFilters,
    getNodeLogs,
    getNodeResponse,
    getNodeEdges,
    executeNode,
    disableNode,
  } = useConnectorData();

  // -----------------------------------------------------------------------
  // Keyboard navigation — Escape returns from drill / radial to cards
  // -----------------------------------------------------------------------

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (state.selectedNode) {
          selectNode(null);
        } else if (viewMode === 'drill') {
          setDrillCluster(null);
          setViewMode('cards');
        } else if (viewMode === 'radial') {
          setViewMode('cards');
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [viewMode, state.selectedNode, selectNode]);

  // -----------------------------------------------------------------------
  // Resize observer
  // -----------------------------------------------------------------------

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        setDimensions({ width: Math.floor(width), height: Math.floor(height) });
      }
    });

    observer.observe(container);

    const rect = container.getBoundingClientRect();
    setDimensions({ width: Math.floor(rect.width), height: Math.floor(rect.height) });

    return () => observer.disconnect();
  }, []);

  // -----------------------------------------------------------------------
  // Zoom handlers
  // -----------------------------------------------------------------------

  const handleZoomIn = useCallback(() => {
    setZoom(Math.min(state.zoom + ZOOM_STEP, MAX_ZOOM));
  }, [state.zoom, setZoom]);

  const handleZoomOut = useCallback(() => {
    setZoom(Math.max(state.zoom - ZOOM_STEP, MIN_ZOOM));
  }, [state.zoom, setZoom]);

  const handleResetView = useCallback(() => {
    resetFilters();
  }, [resetFilters]);

  const handleWheel = useCallback(
    (e: React.WheelEvent) => {
      e.preventDefault();
      const delta = e.deltaY > 0 ? -ZOOM_STEP : ZOOM_STEP;
      setZoom(Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, state.zoom + delta)));
    },
    [state.zoom, setZoom]
  );

  // -----------------------------------------------------------------------
  // Modal
  // -----------------------------------------------------------------------

  const selectedNodeData: ConnectorNode | null = useMemo(() => {
    if (!state.selectedNode) return null;
    return state.nodes.find((n) => n.id === state.selectedNode) ?? null;
  }, [state.selectedNode, state.nodes]);

  const selectedNodeLogs = useMemo(() => {
    if (!state.selectedNode) return [];
    return getNodeLogs(state.selectedNode);
  }, [state.selectedNode, getNodeLogs]);

  const selectedNodeResponse = useMemo(() => {
    if (!state.selectedNode) return null;
    return getNodeResponse(state.selectedNode);
  }, [state.selectedNode, getNodeResponse]);

  const selectedNodeEdges = useMemo(() => {
    if (!state.selectedNode) return [];
    return getNodeEdges(state.selectedNode);
  }, [state.selectedNode, getNodeEdges]);

  const handleModalClose = useCallback(() => {
    selectNode(null);
  }, [selectNode]);

  const handleExecute = useCallback(
    (nodeId: string, payload?: Record<string, unknown>) => { executeNode(nodeId, payload); },
    [executeNode]
  );

  const handleDisable = useCallback(
    (nodeId: string) => { disableNode(nodeId); selectNode(null); },
    [disableNode, selectNode]
  );

  // -----------------------------------------------------------------------
  // Cluster stats for cards
  // -----------------------------------------------------------------------

  const clusterStats = useMemo(() => {
    const map: Record<string, { total: number; online: number; error: number; argus: number; argusOnline: number }> = {};
    for (const cm of CLUSTER_META) {
      const nodes = state.nodes.filter((n) => n.cluster === cm.cluster);
      map[cm.cluster] = {
        total: nodes.length,
        online: nodes.filter((n) => n.status === 'online').length,
        error: nodes.filter((n) => n.status === 'error').length,
        argus: nodes.filter((n) => n.source === 'argus').length,
        argusOnline: nodes.filter((n) => n.source === 'argus' && n.status === 'online').length,
      };
    }
    return map;
  }, [state.nodes]);

  const globalStats = useMemo(() => {
    const total = state.nodes.length;
    const online = state.nodes.filter((n) => n.status === 'online').length;
    const argusNodes = state.nodes.filter((n) => n.source === 'argus');
    const argusOnline = argusNodes.filter((n) => n.status === 'online').length;
    return { total, online, argusTotal: argusNodes.length, argusOnline };
  }, [state.nodes]);

  // -----------------------------------------------------------------------
  // Drill-down handlers
  // -----------------------------------------------------------------------

  const handleCardClick = useCallback((cluster: ClusterType) => {
    setDrillCluster(cluster);
    setViewMode('drill');
  }, []);

  const handleBackToCards = useCallback(() => {
    setViewMode('cards');
    setDrillCluster(null);
    selectNode(null);
  }, [selectNode]);

  const handleShowRadial = useCallback(() => {
    setViewMode('radial');
    setDrillCluster(null);
  }, []);

  // -----------------------------------------------------------------------
  // Drill-down: nodes for selected cluster
  // -----------------------------------------------------------------------

  const drillNodes = useMemo(() => {
    if (!drillCluster) return [];
    return state.nodes.filter((n) => n.cluster === drillCluster);
  }, [drillCluster, state.nodes]);

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  return (
    <div
      ref={containerRef}
      className="connector-map"
      onWheel={viewMode === 'radial' ? handleWheel : undefined}
    >
      {/* Stats bar (top-right) */}
      <div
        style={{
          position: 'absolute',
          top: 16,
          right: 16,
          display: 'flex',
          gap: 16,
          zIndex: 100,
          fontFamily: "'Segoe UI', system-ui, sans-serif",
          fontSize: 10,
          color: '#64748b',
        }}
      >
        <span>
          Nodes:{' '}
          <span style={{ color: '#e2e8f0', fontWeight: 600 }}>
            {globalStats.online}/{globalStats.total}
          </span>{' '}
          online
        </span>
        <span>
          ARGUS:{' '}
          <span style={{ color: globalStats.argusOnline > 0 ? '#00ff88' : '#ff3366', fontWeight: 600 }}>
            {globalStats.argusOnline > 0 ? 'CONNECTED' : 'OFFLINE'}
          </span>
        </span>
      </div>

      {/* View mode toggle (top-left) */}
      <div style={{ position: 'absolute', top: 16, left: 16, display: 'flex', gap: 6, zIndex: 100 }}>
        {viewMode !== 'cards' && (
          <button
            onClick={handleBackToCards}
            style={{
              background: 'rgba(15,20,35,0.85)', border: '1px solid rgba(109,120,255,0.2)',
              color: '#e2e8f0', borderRadius: 6, padding: '4px 12px', fontSize: 11,
              cursor: 'pointer', fontFamily: "'Segoe UI', system-ui, sans-serif",
            }}
          >
            {drillCluster ? `\u2190 All Clusters` : `\u2190 Cards`}
          </button>
        )}
        {viewMode === 'cards' && (
          <button
            onClick={handleShowRadial}
            style={{
              background: 'rgba(15,20,35,0.85)', border: '1px solid rgba(109,120,255,0.2)',
              color: '#94a3b8', borderRadius: 6, padding: '4px 12px', fontSize: 11,
              cursor: 'pointer', fontFamily: "'Segoe UI', system-ui, sans-serif",
            }}
          >
            Radial View
          </button>
        )}
      </div>

      {/* ═══ CARDS VIEW (default) ═══ */}
      {viewMode === 'cards' && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
          gap: 16,
          padding: '56px 24px 24px',
          maxWidth: 1200,
          margin: '0 auto',
          width: '100%',
        }}>
          {CLUSTER_META.map((cm) => {
            const s = clusterStats[cm.cluster];
            const color = CLUSTER_COLORS[cm.cluster];
            const allOk = s.error === 0 && s.online > 0;
            const statusColor = allOk ? STATUS_COLORS.online : s.error > 0 ? STATUS_COLORS.error : STATUS_COLORS.offline;
            const statusLabel = allOk ? 'OK' : s.error > 0 ? `${s.error} ERROR` : 'OFFLINE';

            return (
              <div
                key={cm.cluster}
                onClick={() => handleCardClick(cm.cluster)}
                style={{
                  background: 'rgba(15,20,35,0.7)',
                  border: `1px solid ${color}33`,
                  borderTop: `2px solid ${color}88`,
                  borderRadius: 10,
                  padding: '18px 20px',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  position: 'relative',
                  overflow: 'hidden',
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLDivElement).style.borderColor = `${color}66`;
                  (e.currentTarget as HTMLDivElement).style.boxShadow = `0 0 20px ${color}15`;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLDivElement).style.borderColor = `${color}33`;
                  (e.currentTarget as HTMLDivElement).style.boxShadow = 'none';
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                  <span style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                    {cm.icon} {cm.label}
                  </span>
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5,
                    fontSize: 9, fontWeight: 700, color: statusColor,
                    fontFamily: "'Segoe UI', system-ui, sans-serif",
                  }}>
                    <span style={{
                      width: 6, height: 6, borderRadius: '50%',
                      background: statusColor, boxShadow: `0 0 6px ${statusColor}`,
                      display: 'inline-block',
                    }} />
                    {statusLabel}
                  </span>
                </div>
                <div style={{
                  display: 'flex', gap: 12, fontSize: 11, color: '#94a3b8',
                  fontFamily: "'Segoe UI', system-ui, sans-serif",
                }}>
                  <span>{s.total} Nodes</span>
                  <span style={{ color: '#e2e8f0' }}>{s.online} Online</span>
                  {s.argus > 0 && (
                    <span style={{ color: s.argusOnline > 0 ? '#ffaa00' : '#4b5563' }}>
                      ARGUS: {s.argusOnline}/{s.argus}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ═══ DRILL-DOWN VIEW (cluster nodes grid) ═══ */}
      {viewMode === 'drill' && drillCluster && (
        <div style={{ padding: '56px 24px 24px', maxWidth: 1200, margin: '0 auto', width: '100%' }}>
          <div style={{
            fontSize: 18, fontWeight: 700, color: CLUSTER_COLORS[drillCluster],
            marginBottom: 16, fontFamily: "'Segoe UI', system-ui, sans-serif",
          }}>
            {CLUSTER_META.find((c) => c.cluster === drillCluster)?.icon}{' '}
            {CLUSTER_META.find((c) => c.cluster === drillCluster)?.label}{' '}
            <span style={{ fontSize: 12, color: '#64748b', fontWeight: 400 }}>
              — {drillNodes.length} nodes
            </span>
          </div>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
            gap: 10,
          }}>
            {drillNodes.map((node) => {
              const color = CLUSTER_COLORS[node.cluster];
              const sColor = STATUS_COLORS[node.status] ?? STATUS_COLORS.offline;
              return (
                <div
                  key={node.id}
                  onClick={() => selectNode(node.id)}
                  style={{
                    background: 'rgba(15,20,35,0.7)',
                    border: `1px solid ${color}22`,
                    borderRadius: 8,
                    padding: '12px 14px',
                    cursor: 'pointer',
                    transition: 'border-color 0.15s',
                  }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLDivElement).style.borderColor = `${color}55`; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLDivElement).style.borderColor = `${color}22`; }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                    <span style={{
                      width: 6, height: 6, borderRadius: '50%',
                      background: sColor, boxShadow: `0 0 4px ${sColor}`,
                      display: 'inline-block', flexShrink: 0,
                    }} />
                    <span style={{
                      fontSize: 11, fontWeight: 600, color: '#e2e8f0',
                      fontFamily: "'Segoe UI', system-ui, sans-serif",
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>
                      {node.name}
                    </span>
                  </div>
                  <div style={{ fontSize: 9, color: '#64748b', fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                    {node.source === 'argus' ? 'ARGUS' : 'Sentinel'}
                    {node.ipcChannel ? ` \u00B7 ${node.ipcChannel}` : ''}
                    {node.lastResponseMs > 0 ? ` \u00B7 ${Math.round(node.lastResponseMs)}ms` : ''}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ═══ RADIAL VIEW (full map) ═══ */}
      {viewMode === 'radial' && (
        <>
          <MapControls
            zoom={state.zoom}
            filters={state.filters}
            onZoomIn={handleZoomIn}
            onZoomOut={handleZoomOut}
            onResetView={handleResetView}
            onToggleCluster={toggleCluster}
          />

          {dimensions.width > 0 && dimensions.height > 0 && (
            <RadialLayout
              nodes={filteredNodes}
              edges={filteredEdges}
              width={dimensions.width}
              height={dimensions.height}
              zoom={state.zoom}
              selectedNode={state.selectedNode}
              hoveredNode={state.hoveredNode}
              onSelectNode={selectNode}
              onHoverNode={hoverNode}
            />
          )}
        </>
      )}

      {/* Node detail modal */}
      {selectedNodeData && (
        <NodeModal
          node={selectedNodeData}
          logs={selectedNodeLogs}
          edges={selectedNodeEdges}
          lastResponse={selectedNodeResponse}
          allNodes={state.nodes}
          loading={false}
          onClose={handleModalClose}
          onExecute={handleExecute}
          onDisable={handleDisable}
        />
      )}
    </div>
  );
};

export default ConnectorMap;
