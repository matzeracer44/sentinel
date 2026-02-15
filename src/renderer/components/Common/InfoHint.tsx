import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

export interface InfoHintDetails {
  label: string;
  value: string;
}

interface InfoHintProps {
  /** Optional label rendered before the question button */
  label?: string;
  /** Headline for the info panel */
  title: string;
  /** Body description rendered under the title */
  description: string;
  /** Optional bullet list for extra context */
  details?: InfoHintDetails[];
  /** Preferred alignment of the popover */
  placement?: 'top' | 'bottom';
  /** Optional aria-label override for the toggle button */
  ariaLabel?: string;
}

const InfoHint: React.FC<InfoHintProps> = ({
  label,
  title,
  description,
  details,
  placement = 'top',
  ariaLabel,
}) => {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const tooltipRef = useRef<HTMLDivElement | null>(null);
  const [tooltipStyle, setTooltipStyle] = useState<{ top: number; left: number; placement: 'top' | 'bottom' } | null>(null);

  const updateTooltipPosition = useCallback(() => {
    if (!open || !containerRef.current || !tooltipRef.current) {
      return;
    }
    const anchorRect = containerRef.current.getBoundingClientRect();
    const tooltipRect = tooltipRef.current.getBoundingClientRect();
    let finalPlacement: 'top' | 'bottom' = placement;
    const margin = 8;
    const viewportHeight = window.innerHeight;
    if (finalPlacement === 'top' && anchorRect.top < tooltipRect.height + margin + 12) {
      finalPlacement = 'bottom';
    } else if (finalPlacement === 'bottom' && viewportHeight - anchorRect.bottom < tooltipRect.height + margin + 12) {
      finalPlacement = 'top';
    }
    const rawTop =
      finalPlacement === 'top'
        ? anchorRect.top - tooltipRect.height - margin
        : anchorRect.bottom + margin;
    const top = Math.max(12, rawTop);
    const centeredLeft = anchorRect.left + anchorRect.width / 2 - tooltipRect.width / 2;
    const left = Math.min(
      Math.max(centeredLeft, 12),
      Math.max(12, window.innerWidth - tooltipRect.width - 12)
    );
    setTooltipStyle({ top, left, placement: finalPlacement });
  }, [open, placement]);

  useLayoutEffect(() => {
    if (!open) {
      return;
    }
    updateTooltipPosition();
    window.addEventListener('resize', updateTooltipPosition);
    window.addEventListener('scroll', updateTooltipPosition, true);
    return () => {
      window.removeEventListener('resize', updateTooltipPosition);
      window.removeEventListener('scroll', updateTooltipPosition, true);
    };
  }, [open, updateTooltipPosition]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const handleClick = (event: MouseEvent) => {
      const target = event.target as Node;
      if (!containerRef.current?.contains(target) && !tooltipRef.current?.contains(target)) {
        setOpen(false);
      }
    };
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKey);
    };
  }, [open]);

  return (
    <div ref={containerRef} className="relative inline-flex items-center gap-1">
      {label && <span className="text-[11px] uppercase tracking-wide text-gray-400">{label}</span>}
      <button
        type="button"
        className={`flex h-5 w-5 items-center justify-center rounded-full border text-[11px] font-semibold transition
          ${open ? 'border-cyan-400 text-cyan-200 bg-cyan-500/20' : 'border-gray-700 text-gray-300 hover:border-cyan-500/60 hover:text-cyan-200'}`}
        aria-label={ariaLabel || 'Show info'}
        onClick={() => setOpen((prev) => !prev)}
      >
        ?
      </button>
      {open &&
        createPortal(
          <div
            ref={tooltipRef}
            className="pointer-events-auto fixed z-[999] w-64 rounded-xl border border-cyan-500/30 bg-[#05050f] p-4 shadow-[0_10px_40px_rgba(0,0,0,0.45)]"
            style={{
              top: tooltipStyle?.top ?? 0,
              left: tooltipStyle?.left ?? 0,
              visibility: tooltipStyle ? 'visible' : 'hidden',
            }}
          >
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="text-[11px] uppercase tracking-wide text-gray-400">Sentinel explain</p>
                <h4 className="text-sm font-semibold text-white">{title}</h4>
              </div>
              <span className="text-[10px] font-mono text-gray-500">Ref•{`${title.length}`}</span>
            </div>
            <p className="mt-2 text-[12px] leading-snug text-gray-300">{description}</p>
            {details && details.length > 0 && (
              <ul className="mt-3 space-y-1 border-t border-gray-800 pt-2 text-[11px] text-gray-400">
                {details.map((item) => (
                  <li key={`${item.label}-${item.value}`} className="flex justify-between gap-2">
                    <span>{item.label}</span>
                    <span className="text-white">{item.value}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>,
          document.body
        )}
    </div>
  );
};

export default InfoHint;
