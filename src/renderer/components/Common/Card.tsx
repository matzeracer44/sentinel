import React from 'react';
import { motion } from 'framer-motion';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  elevated?: boolean;
  hoverable?: boolean;
  onClick?: () => void;
}

const Card: React.FC<CardProps> = ({
  children,
  className = '',
  elevated = false,
  hoverable = false,
  onClick,
}) => {
  const baseClasses = elevated ? 'glass-elevated' : 'glass';
  const interactiveClasses = hoverable || onClick ? 'cursor-pointer' : '';

  return (
    <motion.div
      onClick={onClick}
      className={`${baseClasses} rounded-lg p-6 ${interactiveClasses} ${className}`}
      whileHover={hoverable || onClick ? { scale: 1.02 } : {}}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
    >
      {children}
    </motion.div>
  );
};

export default Card;
