import React from 'react';

export const VelLogo: React.FC<{ className?: string }> = ({ className = 'w-7 h-7' }) => (
  <svg className={className} viewBox="0 0 100 100" fill="none" aria-hidden="true">
    <path d="M50 15L85 85H70L50 45L30 85H15L50 15Z" fill="#00CFE8" />
    <circle cx="50" cy="35" r="5" fill="#FFFFFF" />
  </svg>
);
