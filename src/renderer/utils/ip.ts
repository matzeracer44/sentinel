export function normalizeIpAddress(ip?: string | null): string {
  if (!ip) {
    return '';
  }
  return ip.trim();
}

export function isPrivateIP(ip?: string | null): boolean {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) {
    return false;
  }

  if (normalized === '::' || normalized === '::1' || normalized === '0.0.0.0') {
    return true;
  }

  if (normalized === 'localhost') {
    return true;
  }

  if (normalized.startsWith('127.')) {
    return true;
  }

  if (normalized.startsWith('10.')) {
    return true;
  }

  if (normalized.startsWith('192.168.')) {
    return true;
  }

  if (normalized.startsWith('0.')) {
    return true;
  }

  if (normalized.startsWith('172.')) {
    const octets = normalized.split('.');
    if (octets.length >= 2) {
      const second = Number(octets[1]);
      if (second >= 16 && second <= 31) {
        return true;
      }
    }
  }

  if (normalized.toLowerCase().startsWith('fe80::')) {
    return true;
  }

  return false;
}
