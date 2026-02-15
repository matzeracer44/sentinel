import React, { createContext, useState, ReactNode } from 'react';

interface AdminContextType {
  isAdmin: boolean;
  setIsAdmin: (value: boolean) => void;
  showAdminModal: boolean;
  setShowAdminModal: (value: boolean) => void;
  showLimitedBanner: boolean;
  setShowLimitedBanner: (value: boolean) => void;
}

export const AdminContext = createContext<AdminContextType | undefined>(undefined);

export const AdminProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [isAdmin, setIsAdmin] = useState(false);
  const [showAdminModal, setShowAdminModal] = useState(false);
  const [showLimitedBanner, setShowLimitedBanner] = useState(false);

  return (
    <AdminContext.Provider value={{ isAdmin, setIsAdmin, showAdminModal, setShowAdminModal, showLimitedBanner, setShowLimitedBanner }}>
      {children}
    </AdminContext.Provider>
  );
};

export const useAdmin = () => {
  const context = React.useContext(AdminContext);
  if (!context) {
    throw new Error('useAdmin must be used within AdminProvider');
  }
  return context;
};
