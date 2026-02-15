import React from 'react';

interface ActionBarProps {
  onUndo?: () => void;
  onRedo?: () => void;
  canUndo?: boolean;
  canRedo?: boolean;
  undoLabel?: string;
  redoLabel?: string;
  children?: React.ReactNode;
}

const ActionBar: React.FC<ActionBarProps> = ({
  onUndo,
  onRedo,
  canUndo = false,
  canRedo = false,
  undoLabel = 'Undo',
  redoLabel = 'Redo',
  children,
}) => {
  return (
    <div className="flex items-center gap-2 p-3 bg-dark-elevated/50 rounded-lg border border-dark-border flex-wrap">
      {/* Undo Button */}
      {onUndo && (
        <button
          onClick={onUndo}
          disabled={!canUndo}
          title={undoLabel}
          className={`px-3 py-2 rounded font-medium text-sm transition-colors ${
            canUndo
              ? 'bg-accent-cyan-DEFAULT/20 text-accent-cyan-DEFAULT hover:bg-accent-cyan-DEFAULT/30 cursor-pointer'
              : 'bg-gray-700/30 text-gray-600 cursor-not-allowed opacity-50'
          }`}
        >
          ↶ {undoLabel}
        </button>
      )}

      {/* Redo Button */}
      {onRedo && (
        <button
          onClick={onRedo}
          disabled={!canRedo}
          title={redoLabel}
          className={`px-3 py-2 rounded font-medium text-sm transition-colors ${
            canRedo
              ? 'bg-accent-cyan-DEFAULT/20 text-accent-cyan-DEFAULT hover:bg-accent-cyan-DEFAULT/30 cursor-pointer'
              : 'bg-gray-700/30 text-gray-600 cursor-not-allowed opacity-50'
          }`}
        >
          ↷ {redoLabel}
        </button>
      )}

      {/* Separator */}
      {(onUndo || onRedo) && children && <div className="w-px h-6 bg-dark-border" />}

      {/* Custom Actions */}
      <div className="flex gap-2 flex-wrap flex-1">{children}</div>
    </div>
  );
};

export default ActionBar;
