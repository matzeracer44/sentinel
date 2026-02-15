import React from 'react';
import { motion } from 'framer-motion';

interface ButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'danger' | 'success';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  loading?: boolean;
  fullWidth?: boolean;
  className?: string;
}

const Button: React.FC<ButtonProps> = ({
  children,
  onClick,
  variant = 'primary',
  size = 'md',
  disabled = false,
  loading = false,
  fullWidth = false,
  className = '',
}) => {
  const baseClasses = 'font-semibold rounded-lg transition-all duration-200 flex items-center justify-center gap-2';

  const variantClasses = {
    primary: 'bg-accent-cyan-DEFAULT text-dark-bg hover:bg-accent-cyan-light disabled:bg-accent-cyan-DEFAULT/50',
    secondary: 'bg-dark-elevated text-gray-300 hover:bg-dark-border disabled:bg-dark-elevated/50',
    danger: 'bg-threat-danger text-white hover:bg-threat-danger/80 disabled:bg-threat-danger/50',
    success: 'bg-accent-green-DEFAULT text-white hover:bg-accent-green-DEFAULT/80 disabled:bg-accent-green-DEFAULT/50',
  };

  const sizeClasses = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg',
  };

  const widthClass = fullWidth ? 'w-full' : '';

  return (
    <motion.button
      onClick={onClick}
      disabled={disabled || loading}
      className={`${baseClasses} ${variantClasses[variant]} ${sizeClasses[size]} ${widthClass} ${className} ${
        disabled || loading ? 'cursor-not-allowed opacity-50' : ''
      }`}
      whileHover={!disabled && !loading ? { scale: 1.02 } : {}}
      whileTap={!disabled && !loading ? { scale: 0.98 } : {}}
    >
      {loading && (
        <div className="animate-spin border-2 border-current border-t-transparent rounded-full w-4 h-4" />
      )}
      {children}
    </motion.button>
  );
};

export default Button;
