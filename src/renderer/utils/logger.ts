export const debug = (...args: any[]) => console.log('[Sentinel Debug]', ...args);

export const logger = {
  log: (...args: any[]) => console.log('[Sentinel]', ...args),
  error: (...args: any[]) => console.error('[Sentinel Error]', ...args),
  warn: (...args: any[]) => console.warn('[Sentinel Warn]', ...args),
  info: (...args: any[]) => console.info('[Sentinel Info]', ...args),
  debug,
};

export default logger;
