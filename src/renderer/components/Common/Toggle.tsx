import React from 'react';
import { motion } from 'framer-motion';

interface ToggleProps {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  hint?: string;
}

const Toggle: React.FC<ToggleProps> = ({
  label,
  checked,
  onChange,
  disabled = false,
  hint,
}) => {
  return (
    <div className="flex items-center justify-between gap-4 p-3 bg-dark-elevated/50 rounded-lg hover:bg-dark-elevated/70 transition-colors">
      <div>
        <label className={`font-medium text-sm ${disabled ? 'text-gray-600' : 'text-white'}`}>
          {label}
        </label>
        {hint && <p className="text-xs text-gray-500 mt-1">{hint}</p>}
      </div>

      {/* Toggle Switch */}
      <motion.button
        onClick={() => !disabled && onChange(!checked)}
        disabled={disabled}
        className={`relative inline-flex items-center h-6 w-11 rounded-full transition-colors ${
          checked ? 'bg-accent-cyan-DEFAULT' : 'bg-gray-600'
        } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
      >
        <motion.div
          animate={{ x: checked ? 20 : 2 }}
          transition={{ duration: 0.2 }}
          className="inline-block w-5 h-5 transform bg-white rounded-full"
        />
      </motion.button>
    </div>
  );
};

export default Toggle;
