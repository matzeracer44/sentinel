import { useState, useEffect } from 'react';

const usePollingEnabled = () => {
  const [isEnabled, setIsEnabled] = useState(true);

  useEffect(() => {
    const handleVisibilityChange = () => {
      setIsEnabled(!document.hidden);
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  return isEnabled;
};

export default usePollingEnabled;
export { usePollingEnabled };
