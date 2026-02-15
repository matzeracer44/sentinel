import React, { useState } from 'react';
import { motion } from 'framer-motion';

interface ExpandableProps {
  title: string;
  icon?: string;
  badge?: number | string;
  defaultExpanded?: boolean;
  children: React.ReactNode;
  onToggle?: (isExpanded: boolean) => void;
}

const Expandable: React.FC<ExpandableProps> = ({
  title,
  icon,
  badge,
  defaultExpanded = false,
  children,
  onToggle,
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  const handleToggle = () => {
    const newState = !isExpanded;
    setIsExpanded(newState);
    onToggle?.(newState);
  };

  return (
    <div className="border border-dark-border rounded-lg overflow-hidden bg-dark-elevated/50">
      {/* Header */}
      <button
        onClick={handleToggle}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-dark-elevated transition-colors group cursor-pointer"
      >
        <div className="flex items-center gap-3">
          {/* Arrow Icon */}
          <motion.div
            animate={{ rotate: isExpanded ? 90 : 0 }}
            transition={{ duration: 0.2 }}
            className="text-accent-cyan-DEFAULT"
          >
            ▶
          </motion.div>

          {/* Icon & Title */}
          <div className="flex items-center gap-2">
            {icon && <span className="text-lg">{icon}</span>}
            <span className="font-semibold text-white">{title}</span>
          </div>
        </div>

        {/* Badge */}
        {badge !== undefined && (
          <div className="px-2 py-1 bg-accent-cyan-DEFAULT/20 border border-accent-cyan-DEFAULT/30 rounded text-xs font-medium text-accent-cyan-DEFAULT">
            {badge}
          </div>
        )}
      </button>

      {/* Content */}
      <motion.div
        initial={{ height: 0, opacity: 0 }}
        animate={{
          height: isExpanded ? 'auto' : 0,
          opacity: isExpanded ? 1 : 0,
        }}
        transition={{ duration: 0.2 }}
        className="overflow-hidden"
      >
        <div className="px-4 py-3 border-t border-dark-border bg-dark-bg/50">
          {children}
        </div>
      </motion.div>
    </div>
  );
};

export default Expandable;
