import React from 'react';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'success' | 'error' | 'warning' | 'info' | 'default';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  size = 'md',
  className = '',
}) => {
  const variantClasses = {
    success: 'bg-accent-green-DEFAULT/20 text-accent-green-DEFAULT border-accent-green-DEFAULT/30',
    error: 'bg-threat-danger/20 text-threat-danger border-threat-danger/30',
    warning: 'bg-threat-warning/20 text-threat-warning border-threat-warning/30',
    info: 'bg-accent-cyan-DEFAULT/20 text-accent-cyan-DEFAULT border-accent-cyan-DEFAULT/30',
    default: 'bg-dark-elevated text-gray-300 border-dark-border',
  };

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-3 py-1 text-sm',
    lg: 'px-4 py-1.5 text-base',
  };

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border font-semibold ${variantClasses[variant]} ${sizeClasses[size]} ${className}`}
    >
      {children}
    </span>
  );
};

export default Badge;
