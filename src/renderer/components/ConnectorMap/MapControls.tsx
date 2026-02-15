/**
 * Sentinel Unified — MapControls
 * Zoom buttons, reset, and cluster filter chips for the connector map.
 */

import React, { useCallback } from 'react';
import type { ClusterType, ConnectorMapFilters } from '../../types/connectorMap';
import { CLUSTER_COLORS, CLUSTER_SECTORS } from './connectorMapTheme';

interface MapControlsProps {
  zoom: number;
  filters: ConnectorMapFilters;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onResetView: () => void;
  onToggleCluster: (cluster: ClusterType) => void;
}

const ALL_CLUSTERS: ClusterType[] = [
  'firewall',
  'intel',
  'automation',
  'network',
  'dns',
  'system',
  'vault',
];

const CLUSTER_LABELS: Record<ClusterType, string> = {
  core: 'Core',
  firewall: 'Firewall',
  intel: 'Intel',
  automation: 'Auto',
  network: 'Network',
  dns: 'DNS',
  system: 'System',
  vault: 'Vault',
};

const MapControls: React.FC<MapControlsProps> = React.memo(
  ({ zoom, filters, onZoomIn, onZoomOut, onResetView, onToggleCluster }) => {
    return (
      <>
        {/* Zoom controls (bottom-left) */}
        <div className="map-controls">
          <button
            className="map-control-btn"
            onClick={onZoomIn}
            title="Zoom In"
            aria-label="Zoom In"
          >
            +
          </button>
          <button
            className="map-control-btn"
            onClick={onZoomOut}
            title="Zoom Out"
            aria-label="Zoom Out"
          >
            −
          </button>
          <button
            className="map-control-btn"
            onClick={onResetView}
            title="Reset View"
            aria-label="Reset View"
          >
            ⟲
          </button>
          <div
            style={{
              color: '#64748b',
              fontSize: 9,
              textAlign: 'center',
              marginTop: 2,
              fontFamily: "'Segoe UI', system-ui, sans-serif",
            }}
          >
            {Math.round(zoom * 100)}%
          </div>
        </div>

        {/* Cluster filter bar (top-center) */}
        <div className="map-filter-bar">
          {ALL_CLUSTERS.map((cluster) => {
            const isActive = filters.clusters.includes(cluster);
            const color = CLUSTER_COLORS[cluster];
            return (
              <button
                key={cluster}
                className={`filter-chip ${isActive ? 'filter-chip--active' : 'filter-chip--inactive'}`}
                style={{
                  background: isActive ? `${color}18` : 'transparent',
                  borderColor: isActive ? `${color}44` : 'transparent',
                  color: color,
                }}
                onClick={() => onToggleCluster(cluster)}
                title={`Toggle ${CLUSTER_LABELS[cluster]}`}
              >
                {CLUSTER_LABELS[cluster]}
              </button>
            );
          })}
        </div>
      </>
    );
  }
);

MapControls.displayName = 'MapControls';

export default MapControls;
