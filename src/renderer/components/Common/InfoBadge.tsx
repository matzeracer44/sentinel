/**
 * SENTINEL — InfoBadge Component
 * Clickable badge that reveals a beginner-friendly German explanation popup.
 * Replaces cryptic abbreviation badges (DSGVO, OSOP, BSI, TOTP, IoC, etc.)
 * with interactive, accessible info panels.
 */

import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { AnimatePresence, motion } from 'framer-motion';

/* ─── Glossary: All abbreviations with beginner-friendly German explanations ─── */

export interface GlossaryEntry {
  short: string;
  full: string;
  description: string;
  color: string;
  bgColor: string;
  article?: string;
}

export const GLOSSARY: Record<string, GlossaryEntry> = {
  DSGVO: {
    short: 'Datenschutz',
    full: 'Datenschutz-Grundverordnung (DSGVO)',
    description:
      'EU-Gesetz zum Schutz Ihrer pers\u00f6nlichen Daten. Sentinel verarbeitet alles lokal auf Ihrem Ger\u00e4t \u2014 keine Daten werden an Server gesendet.',
    color: '#00e676',
    bgColor: 'rgba(0,230,118,0.12)',
  },
  'DSGVO Art.5': {
    short: 'Datenminimierung',
    full: 'DSGVO Artikel 5 \u2014 Datenminimierung',
    description:
      'Es werden nur die Daten verarbeitet, die f\u00fcr die Sicherheitsanalyse notwendig sind. Keine \u00fcberfl\u00fcssige Speicherung.',
    color: '#00e676',
    bgColor: 'rgba(0,230,118,0.12)',
    article: 'Art.5',
  },
  'DSGVO Art.17': {
    short: 'Recht auf L\u00f6schung',
    full: 'DSGVO Artikel 17 \u2014 Recht auf L\u00f6schung',
    description:
      'Beim Beenden von Sentinel werden alle Sitzungsdaten sicher gel\u00f6scht. Nur Ihre Einstellungen bleiben erhalten.',
    color: '#00e676',
    bgColor: 'rgba(0,230,118,0.12)',
    article: 'Art.17',
  },
  'DSGVO Art.25': {
    short: 'Datenschutz ab Werk',
    full: 'DSGVO Artikel 25 \u2014 Datenschutz durch Technikgestaltung',
    description:
      'Alle Schutzfunktionen sind standardm\u00e4\u00dfig aktiviert. Ihre Privatsph\u00e4re wird ab dem ersten Start gesch\u00fctzt.',
    color: '#00e676',
    bgColor: 'rgba(0,230,118,0.12)',
    article: 'Art.25',
  },
  'DSGVO Art.32': {
    short: 'Verschl\u00fcsselung',
    full: 'DSGVO Artikel 32 \u2014 Sicherheit der Verarbeitung',
    description:
      'Ihre Daten werden mit milit\u00e4rischer Verschl\u00fcsselung (AES-256) gesch\u00fctzt. Selbst bei Diebstahl sind sie unlesbar.',
    color: '#00e676',
    bgColor: 'rgba(0,230,118,0.12)',
    article: 'Art.32',
  },
  OSOP: {
    short: 'Einmal-Sitzung',
    full: 'One-Session-Only Protocol (OSOP)',
    description:
      'Wie ein Inkognito-Modus f\u00fcr die gesamte Sicherheitssoftware: Nach dem Schlie\u00dfen werden alle Aktivit\u00e4tsdaten sicher gel\u00f6scht. Keine R\u00fcckst\u00e4nde.',
    color: '#00e676',
    bgColor: 'rgba(0,230,118,0.12)',
  },
  BSI: {
    short: 'IT-Sicherheit',
    full: 'Bundesamt f\u00fcr Sicherheit in der Informationstechnik',
    description:
      'Die deutsche Bundesbeh\u00f6rde f\u00fcr IT-Sicherheitsstandards. Sentinel erf\u00fcllt deren Empfehlungen f\u00fcr sichere Software.',
    color: '#00b0ff',
    bgColor: 'rgba(0,176,255,0.12)',
  },
  'BSI APP.6': {
    short: 'Software-Integrit\u00e4t',
    full: 'BSI APP.6 \u2014 Allgemeine Software',
    description:
      'BSI-Standard f\u00fcr sichere Software: Pr\u00fcfsummen, Integrit\u00e4tschecks und Lieferketten-\u00dcberwachung. Erkennt Manipulationen.',
    color: '#00b0ff',
    bgColor: 'rgba(0,176,255,0.12)',
  },
  TOTP: {
    short: 'Authenticator-Code',
    full: 'Zeitbasierter Einmalcode (TOTP)',
    description:
      'Alle 30 Sekunden erzeugt Ihre Authenticator-App (z.B. Google Authenticator) einen neuen 6-stelligen Code. Selbst wenn jemand Ihre PIN kennt, braucht er zus\u00e4tzlich Ihr Smartphone.',
    color: 'var(--s-cyan)',
    bgColor: 'rgba(60,240,255,0.08)',
  },
  MFA: {
    short: 'Zwei-Faktor-Schutz',
    full: 'Multi-Faktor-Authentifizierung (MFA)',
    description:
      'Zus\u00e4tzlich zur PIN wird ein zweiter Beweis ben\u00f6tigt (z.B. Authenticator-App). Selbst bei Diebstahl Ihrer PIN bleibt Ihr Konto gesch\u00fctzt.',
    color: 'var(--s-cyan)',
    bgColor: 'rgba(60,240,255,0.08)',
  },
  IoC: {
    short: 'Bedrohungshinweis',
    full: 'Indicator of Compromise (IoC)',
    description:
      'Ein Hinweis auf eine Bedrohung: eine IP-Adresse, Domain oder Datei-Hash, die als b\u00f6sartig bekannt ist. Sentinel pr\u00fcft automatisch gegen lokale Datenbanken.',
    color: 'var(--s-red)',
    bgColor: 'rgba(255,95,95,0.12)',
  },
  SIEM: {
    short: 'Sicherheitsprotokoll',
    full: 'Security Information & Event Management',
    description:
      'Exportiert Sicherheitsereignisse in Standardformate (JSON, CEF, Syslog), die von Sicherheitszentralen und \u00dcberwachungssystemen ausgewertet werden k\u00f6nnen.',
    color: 'var(--s-cyan)',
    bgColor: 'rgba(60,240,255,0.08)',
  },
  SBOM: {
    short: 'Software-St\u00fcckliste',
    full: 'Software Bill of Materials (SBOM)',
    description:
      'Eine Liste aller Programmteile mit Pr\u00fcfsummen. Erkennt, ob jemand die Software manipuliert hat \u2014 wie ein Siegel auf einer Packung.',
    color: 'var(--s-green)',
    bgColor: 'rgba(61,255,143,0.08)',
  },
  'AES-256': {
    short: 'Milit\u00e4rverschl\u00fcsselung',
    full: 'AES-256-GCM Verschl\u00fcsselung',
    description:
      'Die st\u00e4rkste verf\u00fcgbare Verschl\u00fcsselung mit 256-Bit-Schl\u00fcssel. Wird von Milit\u00e4r und Regierungen weltweit eingesetzt. Mit heutiger Technik unknackbar.',
    color: 'var(--s-cyan)',
    bgColor: 'rgba(60,240,255,0.12)',
  },
  YARA: {
    short: 'Malware-Scanner',
    full: 'YARA \u2014 Malware-Signaturerkennung',
    description:
      'Pr\u00fcft Dateien auf bekannte Schadsoftware-Muster (Signaturen). Funktioniert wie ein Virenscanner, l\u00e4uft aber vollst\u00e4ndig offline auf Ihrem Ger\u00e4t.',
    color: 'var(--s-amber)',
    bgColor: 'rgba(255,170,0,0.08)',
  },
  UEBA: {
    short: 'Verhaltensanalyse',
    full: 'User & Entity Behavior Analytics',
    description:
      'Erkennt ungew\u00f6hnliches Verhalten von Programmen und Netzwerkverbindungen. Wenn sich etwas untypisch verh\u00e4lt, wird es als verd\u00e4chtig markiert.',
    color: 'var(--s-purple)',
    bgColor: 'rgba(167,139,250,0.08)',
  },
  LOKAL: {
    short: 'Auf Ihrem Ger\u00e4t',
    full: '100% Lokale Verarbeitung',
    description:
      'Alle Analysen und Scans laufen ausschlie\u00dflich auf Ihrem Computer. Keine Daten verlassen Ihr Ger\u00e4t \u2014 kein Internet erforderlich.',
    color: '#00b0ff',
    bgColor: 'rgba(0,176,255,0.12)',
  },
  MISP: {
    short: 'Bedrohungs-Feeds',
    full: 'Malware Information Sharing Platform',
    description:
      'Offene Datenbanken mit bekannten Bedrohungen (b\u00f6sartige IPs, Domains, Datei-Hashes). Sentinel l\u00e4dt diese herunter und pr\u00fcft lokal dagegen.',
    color: 'var(--s-amber)',
    bgColor: 'rgba(255,170,0,0.08)',
  },
  TLS: {
    short: 'Verschl\u00fcsselte Verbindung',
    full: 'Transport Layer Security (TLS)',
    description:
      'Verschl\u00fcsselt die Verbindung zwischen Ihrem Browser und Webseiten. Der TLS-Inspektor pr\u00fcft Zertifikate auf G\u00fcltigkeit und Vertrauensw\u00fcrdigkeit.',
    color: 'var(--s-cyan)',
    bgColor: 'rgba(60,240,255,0.08)',
  },
  WFP: {
    short: 'Firewall-Kern',
    full: 'Windows Filtering Platform (WFP)',
    description:
      'Der Kernel-Level-Paketfilter von Windows \u2014 die tiefste Ebene der Netzwerksicherheit. Sentinel pr\u00fcft, ob dieser korrekt konfiguriert ist.',
    color: 'var(--s-cyan)',
    bgColor: 'rgba(60,240,255,0.08)',
  },
  RFC: {
    short: 'Internet-Standard',
    full: 'Request for Comments (RFC)',
    description:
      'Offizielle technische Standards des Internets. RFC 6238 definiert z.B. das TOTP-Verfahren f\u00fcr Authenticator-Apps.',
    color: 'var(--s-cyan)',
    bgColor: 'rgba(60,240,255,0.08)',
  },
  ARGUS: {
    short: 'KI-Backend',
    full: 'ARGUS \u2014 Sentinels KI-Analyse-Engine',
    description:
      'Das Python-Backend von Sentinel. ARGUS f\u00fchrt tiefgehende Analysen durch: URL-Scanning, YARA-Malware-Erkennung, UEBA-Verhaltensanalyse und Verschl\u00fcsselung. L\u00e4uft lokal auf Ihrem Ger\u00e4t.',
    color: 'var(--s-red)',
    bgColor: 'rgba(255,95,95,0.08)',
  },
  KOSTENLOS: {
    short: 'Gratis',
    full: 'Kostenlose Open-Source-Daten',
    description:
      'Diese Funktion nutzt ausschlie\u00dflich kostenlose, \u00f6ffentlich verf\u00fcgbare Sicherheitsdaten (z.B. abuse.ch, Feodo Tracker). Keine API-Schl\u00fcssel, keine Abonnements, keine versteckten Kosten.',
    color: '#00e676',
    bgColor: 'rgba(0,230,118,0.08)',
  },
  'KI-GEST\u00dcTZT': {
    short: 'KI-Analyse',
    full: 'KI-gest\u00fctzte Bedrohungsanalyse',
    description:
      'Kombiniert mehrere Analyse-Methoden (YARA-Signaturen + UEBA-Verhaltensanalyse) zu einer automatischen Risikobewertung. Die KI vergibt Punkte f\u00fcr jede Bedrohungskategorie und berechnet ein Gesamtrisiko.',
    color: 'rgba(167,139,250,0.9)',
    bgColor: 'rgba(167,139,250,0.08)',
  },
};

/* ─── InfoBadge Component ─── */

interface InfoBadgeProps {
  /** Glossary key (e.g. 'DSGVO', 'OSOP', 'BSI APP.6') */
  glossaryKey: string;
  /** Override display label */
  label?: string;
  /** Override color */
  color?: string;
  /** Override background */
  bgColor?: string;
  /** Show the article reference (e.g. 'Art.5') */
  showArticle?: boolean;
  /** Size variant */
  size?: 'xs' | 'sm' | 'md';
}

const SIZE_STYLES = {
  xs: { fontSize: '0.5rem', padding: '1px 5px', borderRadius: 3, gap: 3 },
  sm: { fontSize: '0.55rem', padding: '2px 7px', borderRadius: 4, gap: 4 },
  md: { fontSize: '0.625rem', padding: '3px 9px', borderRadius: 5, gap: 5 },
};

const InfoBadge: React.FC<InfoBadgeProps> = ({
  glossaryKey,
  label,
  color: colorOverride,
  bgColor: bgOverride,
  showArticle,
  size = 'sm',
}) => {
  const [open, setOpen] = useState(false);
  const badgeRef = useRef<HTMLButtonElement>(null);
  const popupRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number; below: boolean } | null>(null);

  const entry = GLOSSARY[glossaryKey];
  const displayLabel = label || (entry ? (showArticle && entry.article ? entry.article : glossaryKey) : glossaryKey);
  const c = colorOverride || entry?.color || 'var(--s-text-dim)';
  const bg = bgOverride || entry?.bgColor || 'rgba(109,120,255,0.08)';
  const sizeStyle = SIZE_STYLES[size];

  const updatePosition = useCallback(() => {
    if (!open || !badgeRef.current || !popupRef.current) return;
    const anchor = badgeRef.current.getBoundingClientRect();
    const popup = popupRef.current.getBoundingClientRect();
    const margin = 8;
    let below = false;
    let top = anchor.top - popup.height - margin;
    if (top < 12) {
      top = anchor.bottom + margin;
      below = true;
    }
    let left = anchor.left + anchor.width / 2 - popup.width / 2;
    left = Math.max(12, Math.min(left, window.innerWidth - popup.width - 12));
    setPos({ top, left, below });
  }, [open]);

  useLayoutEffect(() => {
    if (!open) return;
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [open, updatePosition]);

  useEffect(() => {
    if (!open) return;
    const handleClick = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!badgeRef.current?.contains(t) && !popupRef.current?.contains(t)) setOpen(false);
    };
    const handleKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKey);
    };
  }, [open]);

  return (
    <>
      <button
        ref={badgeRef}
        type="button"
        onClick={() => setOpen((p) => !p)}
        style={{
          ...sizeStyle,
          display: 'inline-flex', alignItems: 'center',
          background: bg,
          color: c,
          fontWeight: 700,
          border: 'none',
          cursor: 'pointer',
          letterSpacing: '0.02em',
          lineHeight: 1.2,
          transition: 'all 0.15s',
          outline: 'none',
          ...(open ? { boxShadow: `0 0 8px ${c}44`, filter: 'brightness(1.2)' } : {}),
        }}
        aria-label={`Info: ${entry?.full || glossaryKey}`}
        title={entry ? `${entry.short} \u2014 Klicken f\u00fcr Details` : glossaryKey}
      >
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: sizeStyle.gap }}>
          {displayLabel}
          <span style={{ fontSize: '0.5em', opacity: 0.7, lineHeight: 1 }}>{"\u24d8"}</span>
        </span>
      </button>
      {open && entry && createPortal(
        <AnimatePresence>
          <motion.div
            ref={popupRef}
            initial={{ opacity: 0, y: pos?.below ? -6 : 6, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, scale: 0.97 }}
            transition={{ duration: 0.15 }}
            style={{
              position: 'fixed',
              zIndex: 10000,
              top: pos?.top ?? 0,
              left: pos?.left ?? 0,
              width: 320,
              borderRadius: 14,
              border: `1px solid ${c}40`,
              background: 'rgba(8,10,22,0.97)',
              backdropFilter: 'blur(20px)',
              padding: '16px 18px',
              color: '#e2e8f0',
              boxShadow: `0 8px 32px rgba(0,0,0,0.5), 0 0 20px ${c}15`,
              visibility: pos ? 'visible' : 'hidden',
            }}
          >
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{
                  fontSize: '0.6rem', padding: '2px 7px', borderRadius: 4,
                  background: bg, color: c, fontWeight: 700,
                }}>{glossaryKey}</span>
                <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>{entry.short}</span>
              </div>
              <button
                onClick={() => setOpen(false)}
                style={{
                  background: 'none', border: 'none', color: 'var(--s-text-dim)',
                  cursor: 'pointer', fontSize: '0.8rem', padding: '2px 4px', lineHeight: 1,
                }}
                aria-label="Schlie\u00dfen"
              >{"\u2715"}</button>
            </div>
            {/* Full name */}
            <div style={{
              fontSize: '0.8rem', fontWeight: 700, color: '#f0f1ff', marginBottom: 8,
              fontFamily: 'var(--s-font-display)',
            }}>
              {entry.full}
            </div>
            {/* Description */}
            <div style={{
              fontSize: '0.725rem', color: '#94a3b8', lineHeight: 1.6,
            }}>
              {entry.description}
            </div>
            {/* Footer hint */}
            <div style={{
              marginTop: 12, paddingTop: 10,
              borderTop: '1px solid rgba(109,120,255,0.1)',
              fontSize: '0.6rem', color: 'var(--s-text-dim)',
              display: 'flex', alignItems: 'center', gap: 6,
            }}>
              <span style={{ width: 4, height: 4, borderRadius: '50%', background: c, display: 'inline-block' }} />
              {'Sentinel erf\u00fcllt diesen Standard automatisch'}
            </div>
          </motion.div>
        </AnimatePresence>,
        document.body
      )}
    </>
  );
};

export default InfoBadge;
