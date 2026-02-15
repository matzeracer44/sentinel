import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAdmin } from '../../contexts/AdminContext';

const AdminModal: React.FC = () => {
  const { showAdminModal, setShowAdminModal, setShowLimitedBanner } = useAdmin();
  const [adminError, setAdminError] = useState<string | null>(null);

  const handleRestartAsAdmin = async () => {
    setAdminError(null);
    try {
      const result = await window.electronAPI.admin.restartAsAdmin();
      if (!result.success) {
        setAdminError(`Failed to restart as administrator: ${result.error}`);
      }
    } catch {
      setAdminError('Failed to restart as administrator. Please run Sentinel manually as administrator.');
    }
  };

  const handleContinueLimited = () => {
    setShowAdminModal(false);
    setShowLimitedBanner(true);
  };

  return (
    <AnimatePresence>
      {showAdminModal && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50"
            onClick={handleContinueLimited}
          />

          {/* Modal */}
          <div className="fixed inset-0 flex items-center justify-center z-50 p-4">
            <motion.div
              initial={{ scale: 0.9, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.9, opacity: 0, y: 20 }}
              className="glass-elevated rounded-2xl p-8 max-w-md w-full border-2 border-threat-warning/50"
            >
              {/* Warning Icon */}
              <div className="flex justify-center mb-6">
                <div className="w-20 h-20 rounded-full bg-threat-warning/20 flex items-center justify-center">
                  <span className="text-5xl">⚠️</span>
                </div>
              </div>

              {/* Title */}
              <h2 className="text-2xl font-bold text-white text-center mb-4">
                Administrator Rights Required
              </h2>

              {/* Message */}
              <p className="text-gray-300 text-center mb-6 leading-relaxed">
                Sentinel requires administrator rights for full functionality. Some features like <strong className="text-accent-purple-DEFAULT">Forge optimizations</strong> and <strong className="text-accent-cyan-DEFAULT">real-time data updates</strong> will be limited without elevated privileges.
              </p>

              {/* Features List */}
              <div className="mb-6 p-4 bg-dark-surface rounded-lg">
                <div className="text-xs text-gray-400 mb-2">Limited Features:</div>
                <ul className="space-y-2 text-sm text-gray-300">
                  <li className="flex items-center gap-2">
                    <span className="text-threat-danger">×</span>
                    <span>RAM optimization</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-threat-danger">×</span>
                    <span>Service management</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-threat-danger">×</span>
                    <span>Firewall control</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-threat-danger">×</span>
                    <span>Disk cleanup</span>
                  </li>
                </ul>
              </div>

              {/* Error display */}
              {adminError && (
                <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-sm text-center">
                  {adminError}
                </div>
              )}

              {/* Question */}
              <p className="text-white text-center mb-6 font-semibold">
                Restart as administrator?
              </p>

              {/* Buttons */}
              <div className="flex gap-3">
                <button
                  onClick={handleRestartAsAdmin}
                  className="flex-1 px-6 py-3 bg-accent-green-DEFAULT hover:bg-accent-green-DEFAULT/80 text-white rounded-lg font-bold transition-colors flex items-center justify-center gap-2"
                >
                  <span>🔒</span>
                  <span>Restart as Admin</span>
                </button>

                <button
                  onClick={handleContinueLimited}
                  className="flex-1 px-6 py-3 bg-dark-surface hover:bg-dark-border text-gray-300 hover:text-white rounded-lg font-bold transition-colors"
                >
                  Continue Limited
                </button>
              </div>

              {/* Info */}
              <p className="text-xs text-gray-500 text-center mt-4">
                You can restart as administrator later from the settings menu
              </p>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
};

export default AdminModal;
