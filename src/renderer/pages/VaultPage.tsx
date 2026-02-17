/**
 * SENTINEL UNIFIED — Vault Page
 * Encryption/decryption with ARGUS + local fallback, ARGUS health indicator,
 * secure notes, password generator, whitelist config.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
import InfoBadge from '../components/Common/InfoBadge';
import InputModal, { useInputModal } from '../components/Common/InputModal';
import { useTranslation } from 'react-i18next';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

type Tab = 'encrypt' | 'notes' | 'passwords' | 'shredder' | 'config';

interface CryptoResult {
  text: string;
  engine: 'argus' | 'local' | 'error';
  source?: string;
  hint?: string;
  argusOffline?: boolean;
}

const VaultPage: React.FC = () => {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>('encrypt');
  const [argusOnline, setArgusOnline] = useState<boolean | null>(null);
  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [encryptResult, setEncryptResult] = useState<CryptoResult | null>(null);
  const [decryptResult, setDecryptResult] = useState<CryptoResult | null>(null);
  const [processing, setProcessing] = useState(false);
  const [notes, setNotes] = useState<Array<{ id: string; title: string; createdAt: string; engine?: string }>>([]);
  const [noteTitle, setNoteTitle] = useState('');
  const [noteContent, setNoteContent] = useState('');
  const [notePassword, setNotePassword] = useState('');
  const [openedNote, setOpenedNote] = useState<{ id: string; title: string; content: string } | null>(null);
  const [notesLoading, setNotesLoading] = useState(false);
  const [shredStats, setShredStats] = useState<{ totalShredded: number; totalBytes: number } | null>(null);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [filePassword, setFilePassword] = useState('');
  const [encryptedFiles, setEncryptedFiles] = useState<Array<{ name: string; path: string; size: number; modified: string }>>([]);
  const [dragOver, setDragOver] = useState(false);
  const [fileProcessing, setFileProcessing] = useState(false);
  const [decryptPassword, setDecryptPassword] = useState('');
  const [filesToDecrypt, setFilesToDecrypt] = useState<string[]>([]);
  const [dragOverDecrypt, setDragOverDecrypt] = useState(false);
  const [generatedPw, setGeneratedPw] = useState('');
  const [pwLength, setPwLength] = useState(24);
  const [pwCopied, setPwCopied] = useState(false);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [newWhitelistIp, setNewWhitelistIp] = useState('');
  const { showInput, showAlert, modalProps } = useInputModal();

  const checkArgus = useCallback(async () => {
    try {
      const r = await api()?.argus?.getHealth?.();
      setArgusOnline(r?.data?.status === 'running');
    } catch { setArgusOnline(false); }
  }, []);

  useEffect(() => { checkArgus(); const i = setInterval(checkArgus, 10000); return () => clearInterval(i); }, [checkArgus]);

  const handleEncrypt = async () => {
    if (!plaintext.trim()) return;
    setProcessing(true);
    setEncryptResult(null);
    try {
      const r = await api()?.argus?.encryptData?.(plaintext);
      if (r?.success && r?.data) {
        setEncryptResult({ text: typeof r.data === 'string' ? r.data : JSON.stringify(r.data), engine: r.engine || 'argus' });
        notify.success(`Encrypted via ${r.engine || 'ARGUS'}`);
      } else {
        setEncryptResult({ text: r?.error || 'Encryption failed', engine: 'error' });
        notify.error(r?.error || 'Encryption failed');
      }
    } catch (e: any) { setEncryptResult({ text: String(e), engine: 'error' }); notify.error(e?.message || 'Encryption failed'); }
    setProcessing(false);
  };

  const handleDecrypt = async () => {
    if (!ciphertext.trim()) return;
    setProcessing(true);
    setDecryptResult(null);
    try {
      const r = await api()?.argus?.decryptData?.(ciphertext);
      if (r?.success && r?.data) {
        setDecryptResult({ text: typeof r.data === 'string' ? r.data : JSON.stringify(r.data), engine: r.engine || 'argus', source: r.source });
        notify.success(`Decrypted via ${r.engine || 'ARGUS'}`);
      } else {
        setDecryptResult({
          text: r?.error || 'Decryption failed',
          engine: 'error',
          source: r?.source,
          hint: r?.hint,
          argusOffline: r?.argusOffline,
        });
        notify.error(r?.error || 'Decryption failed');
      }
    } catch (e: any) { setDecryptResult({ text: String(e), engine: 'error' }); notify.error(e?.message || 'Decryption failed'); }
    setProcessing(false);
  };

  const handleStartArgusAndRetry = async () => {
    setProcessing(true);
    try {
      await api()?.argus?.start?.();
      await new Promise((r) => setTimeout(r, 3000));
      await checkArgus();
      await handleDecrypt();
    } catch (e: any) { notify.error(e?.message || 'ARGUS start failed'); setProcessing(false); }
  };

  const fetchEncryptedFiles = useCallback(async () => {
    try {
      const r = await api()?.vault?.getEncryptedFiles?.();
      if (r?.success && Array.isArray(r.files)) setEncryptedFiles(r.files);
    } catch (e: any) { console.warn('[VaultPage] fetchEncryptedFiles:', e?.message); }
  }, []);

  useEffect(() => { if (tab === 'encrypt') fetchEncryptedFiles(); }, [tab, fetchEncryptedFiles]);

  const handleFileSelect = async () => {
    try {
      const r = await api()?.vault?.selectFiles?.();
      if (r?.success && r.files?.length) {
        setSelectedFiles((prev) => [...new Set([...prev, ...r.files])]);
      }
    } catch (e: any) { notify.error(e?.message || 'Dateiauswahl fehlgeschlagen'); }
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
    const files = Array.from(e.dataTransfer.files).map((f) => (f as any).path).filter(Boolean);
    if (files.length) setSelectedFiles((prev) => [...new Set([...prev, ...files])]);
  };

  const handleEncryptFiles = async () => {
    if (!selectedFiles.length || !filePassword.trim()) return;
    setFileProcessing(true);
    try {
      const r = await api()?.vault?.encryptFiles?.(selectedFiles, filePassword);
      if (r?.success) {
        notify.success(`${r.encryptedCount} Datei(en) verschl\u00fcsselt`);
        setSelectedFiles([]);
        setFilePassword('');
        fetchEncryptedFiles();
      } else { notify.error(r?.message || 'Verschl\u00fcsselung fehlgeschlagen'); }
    } catch (e: any) { notify.error(e?.message || 'Verschl\u00fcsselung fehlgeschlagen'); }
    setFileProcessing(false);
  };

  const handleDecryptFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOverDecrypt(false);
    const files = Array.from(e.dataTransfer.files)
      .map((f) => (f as any).path)
      .filter((p: string) => p && p.endsWith('.sentinel'));
    if (files.length) setFilesToDecrypt((prev) => [...new Set([...prev, ...files])]);
    else notify.error('Nur .sentinel-Dateien k\u00f6nnen entschl\u00fcsselt werden');
  };

  const handleDecryptFileSelect = async () => {
    try {
      const r = await api()?.vault?.selectFiles?.();
      if (r?.success && r.files?.length) {
        const sentinelFiles = r.files.filter((f: string) => f.endsWith('.sentinel'));
        if (sentinelFiles.length) setFilesToDecrypt((prev) => [...new Set([...prev, ...sentinelFiles])]);
        else notify.error('Nur .sentinel-Dateien k\u00f6nnen entschl\u00fcsselt werden');
      }
    } catch (e: any) { notify.error(e?.message || 'Dateiauswahl fehlgeschlagen'); }
  };

  const handleDecryptFile = async (filePath: string) => {
    if (!decryptPassword.trim()) { notify.error('Bitte Passwort eingeben'); return; }
    setFileProcessing(true);
    try {
      const r = await api()?.vault?.decryptFile?.(filePath, decryptPassword);
      if (r?.success) {
        notify.success(`Datei entschl\u00fcsselt: ${r.outputPath?.split('\\').pop() || r.outputPath}`);
        setFilesToDecrypt((prev) => prev.filter((f) => f !== filePath));
      } else { notify.error(r?.message || 'Entschl\u00fcsselung fehlgeschlagen (falsches Passwort?)'); }
    } catch (e: any) { notify.error(e?.message || 'Entschl\u00fcsselung fehlgeschlagen'); }
    setFileProcessing(false);
  };

  const handleDecryptAll = async () => {
    if (!filesToDecrypt.length || !decryptPassword.trim()) return;
    setFileProcessing(true);
    let ok = 0;
    let fail = 0;
    for (const fp of filesToDecrypt) {
      try {
        const r = await api()?.vault?.decryptFile?.(fp, decryptPassword);
        if (r?.success) ok++;
        else fail++;
      } catch { fail++; }
    }
    if (ok > 0) notify.success(`${ok} Datei(en) entschl\u00fcsselt`);
    if (fail > 0) notify.error(`${fail} Datei(en) fehlgeschlagen (falsches Passwort?)`);
    setFilesToDecrypt((prev) => prev.slice(ok));
    if (fail === 0) { setFilesToDecrypt([]); setDecryptPassword(''); }
    setFileProcessing(false);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const generatePassword = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
    const arr = new Uint32Array(pwLength);
    crypto.getRandomValues(arr);
    setGeneratedPw(Array.from(arr, (v) => chars[v % chars.length]).join(''));
    setPwCopied(false);
  };

  const copyPassword = () => {
    navigator.clipboard.writeText(generatedPw);
    setPwCopied(true);
    setTimeout(() => setPwCopied(false), 2000);
  };

  const fetchConfig = async () => {
    try {
      const r = await api()?.sentinelConfig?.getConfig?.();
      if (r?.data?.whitelist) setWhitelist(r.data.whitelist);
    } catch (e: any) { console.warn('[VaultPage] fetchWhitelist:', e?.message); }
  };

  const engineBadge = (engine: string) => {
    if (engine === 'argus') return <span className="s-badge s-badge-cyan" style={{ fontSize: '0.55rem' }}>ARGUS</span>;
    if (engine === 'local') return <span className="s-badge s-badge-amber" style={{ fontSize: '0.55rem' }}>LOCAL AES-256</span>;
    return <span className="s-badge s-badge-red" style={{ fontSize: '0.55rem' }}>ERROR</span>;
  };

  const resultColor = (engine: string) => {
    if (engine === 'argus') return 'var(--s-cyan)';
    if (engine === 'local') return 'var(--s-amber)';
    return 'var(--s-red)';
  };

  const fetchNotes = useCallback(async () => {
    setNotesLoading(true);
    try {
      const r = await api()?.vault?.getSecureNotes?.();
      if (r?.success && Array.isArray(r.notes)) setNotes(r.notes);
    } catch (e: any) { console.warn('[VaultPage] fetchNotes:', e?.message); }
    setNotesLoading(false);
  }, []);

  const fetchShredStats = useCallback(async () => {
    try {
      const r = await api()?.vault?.getShredStats?.();
      if (r?.success) setShredStats(r);
    } catch (e: any) { console.warn('[VaultPage] fetchShredStats:', e?.message); }
  }, []);

  const handleSaveNote = async () => {
    if (!noteTitle.trim() || !noteContent.trim() || !notePassword.trim()) return;
    try {
      const r = await api()?.vault?.saveSecureNote?.({ title: noteTitle.trim(), content: noteContent.trim(), password: notePassword });
      if (r?.success) {
        notify.success('Notiz sicher gespeichert');
        setNoteTitle(''); setNoteContent(''); setNotePassword('');
        fetchNotes();
      } else { notify.error(r?.error || 'Notiz konnte nicht gespeichert werden'); }
    } catch (e: any) { notify.error(e?.message || 'Notiz konnte nicht gespeichert werden'); }
  };

  const handleOpenNote = async (noteId: string, password: string) => {
    try {
      const r = await api()?.vault?.openSecureNote?.(noteId, password);
      if (r?.success && r.note) {
        setOpenedNote({ id: noteId, title: r.note.title || '', content: r.note.content || '' });
      } else { notify.error(r?.error || 'Falsches Passwort oder Notiz besch\u00e4digt'); }
    } catch (e: any) { notify.error(e?.message || 'Notiz konnte nicht ge\u00f6ffnet werden'); }
  };

  const handleDeleteNote = async (noteId: string) => {
    try {
      const r = await api()?.vault?.deleteSecureNote?.(noteId);
      if (r?.success) { notify.success('Notiz gel\u00f6scht'); fetchNotes(); setOpenedNote(null); }
      else notify.error(r?.error || 'L\u00f6schen fehlgeschlagen');
    } catch (e: any) { notify.error(e?.message || 'L\u00f6schen fehlgeschlagen'); }
  };

  const TABS: { key: Tab; labelKey: string; count?: number }[] = [
    { key: 'encrypt', labelKey: 'vault.tabs.encryption' },
    { key: 'notes', labelKey: 'vault.tabs.notes', count: notes.length || undefined },
    { key: 'passwords', labelKey: 'vault.tabs.passwords' },
    { key: 'shredder', labelKey: 'vault.tabs.shredder' },
    { key: 'config', labelKey: 'vault.tabs.argus' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ─── Spacy Header ─── */}
      <div className="s-page-header">
        <div className="s-tab-bar">
          {TABS.map((tb) => (
            <button key={tb.key} className={`s-tab ${tab === tb.key ? 's-tab-active' : ''}`} onClick={() => { setTab(tb.key); if (tb.key === 'config') fetchConfig(); if (tb.key === 'notes') fetchNotes(); if (tb.key === 'shredder') fetchShredStats(); }}>
              {t(tb.labelKey)}
              {tb.count !== undefined && <span className="s-tab-badge">{tb.count}</span>}
            </button>
          ))}
        </div>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '3px 10px', borderRadius: 8,
          background: argusOnline ? 'rgba(61,255,143,0.06)' : argusOnline === false ? 'rgba(255,190,61,0.06)' : 'rgba(109,120,255,0.04)',
          border: `1px solid ${argusOnline ? 'rgba(61,255,143,0.18)' : argusOnline === false ? 'rgba(255,190,61,0.18)' : 'rgba(109,120,255,0.12)'}`,
        }}>
          <span style={{
            width: 6, height: 6, borderRadius: '50%',
            background: argusOnline ? 'var(--s-green)' : argusOnline === false ? 'var(--s-amber)' : 'var(--s-text-dim)',
            boxShadow: argusOnline ? '0 0 6px var(--s-green)' : argusOnline === false ? '0 0 6px var(--s-amber)' : 'none',
            animation: argusOnline ? 'pulse-green 2s ease-in-out infinite' : 'none',
          }} />
          <span style={{ fontSize: '0.675rem', fontWeight: 600, color: argusOnline ? 'var(--s-green)' : argusOnline === false ? 'var(--s-amber)' : 'var(--s-text-dim)' }}>
            {argusOnline ? t('dashboard.argusOnline') : argusOnline === false ? t('dashboard.argusOffline') : t('common.loading')}
          </span>
        </div>
      </div>

      {/* Offline banner */}
      {argusOnline === false && (
        <div style={{ padding: '10px 16px', background: 'rgba(255,180,50,0.08)', border: '1px solid rgba(255,180,50,0.2)', borderRadius: 'var(--s-radius-md)', fontSize: '0.8125rem', color: 'var(--s-amber)' }}>
          {'ARGUS-Backend ist offline. Der Tresor verwendet lokale AES-256-GCM-Verschl\u00fcsselung. Lokal verschl\u00fcsselte Daten k\u00f6nnen nicht von ARGUS entschl\u00fcsselt werden und umgekehrt.'}
        </div>
      )}

      <AnimatePresence mode="wait">
        {/* ═══ Dateiverschlüsselung — File Encrypt / Decrypt ═══ */}
        {tab === 'encrypt' && (
          <motion.div key="encrypt" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Encryption Info Bar */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '10px 16px', borderRadius: 10, background: 'rgba(60,240,255,0.03)', border: '1px solid rgba(60,240,255,0.1)', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ display: 'flex', gap: 6 }}>
                  <InfoBadge glossaryKey="AES-256" />
                  <InfoBadge glossaryKey="DSGVO Art.32" />
                </div>
                <span style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)', lineHeight: 1.4 }}>
                  {'Milit\u00e4rische Verschl\u00fcsselung \u2014 256-Bit-Schl\u00fcssel mit authentifizierter Verschl\u00fcsselung. Kein Dritter kann Ihre Daten lesen.'}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                <span style={{ fontSize: '0.55rem', color: 'var(--s-text-dim)' }}>{'St\u00e4rke:'}</span>
                <div style={{ display: 'flex', gap: 2 }}>
                  {[1,2,3,4,5].map(i => (
                    <div key={i} style={{ width: 12, height: 6, borderRadius: 2, background: 'var(--s-green)', boxShadow: '0 0 3px rgba(61,255,143,0.4)' }} />
                  ))}
                </div>
                <span style={{ fontSize: '0.55rem', fontWeight: 700, color: 'var(--s-green)' }}>MAX</span>
              </div>
            </div>

            {/* ─── FILE ENCRYPTION SECTION ─── */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
              {/* LEFT: Encrypt Files */}
              <div className="s-card-spacy" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), var(--s-green))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                    {'Dateien verschl\u00fcsseln'}
                  </span>
                  <div className="s-section-divider" style={{ flex: 1 }} />
                </div>

                {/* Drag & Drop Zone */}
                <div
                  onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); setDragOver(true); }}
                  onDragLeave={(e) => { e.preventDefault(); e.stopPropagation(); setDragOver(false); }}
                  onDrop={handleFileDrop}
                  onClick={handleFileSelect}
                  style={{
                    border: `2px dashed ${dragOver ? 'var(--s-cyan)' : 'rgba(60,240,255,0.15)'}`,
                    borderRadius: 12, padding: '24px 16px', textAlign: 'center', cursor: 'pointer',
                    background: dragOver ? 'rgba(60,240,255,0.06)' : 'rgba(8,8,28,0.3)',
                    transition: 'all 0.2s ease', minHeight: 80,
                    display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 6,
                  }}
                >
                  <span style={{ fontSize: '1.5rem' }}>{dragOver ? '\ud83d\udce5' : '\ud83d\udcc2'}</span>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: dragOver ? 'var(--s-cyan)' : 'var(--s-text-muted)' }}>
                    {dragOver ? 'Dateien hier ablegen' : 'Dateien hierher ziehen oder klicken'}
                  </span>
                  <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>
                    {'Drag & Drop oder Dateiauswahl-Dialog'}
                  </span>
                </div>

                {/* Selected Files List */}
                {selectedFiles.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 140, overflowY: 'auto' }}>
                    <div style={{ fontSize: '0.6rem', fontWeight: 700, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      {`${selectedFiles.length} Datei(en) ausgew\u00e4hlt`}
                    </div>
                    {selectedFiles.map((fp, i) => (
                      <div key={i} style={{
                        display: 'flex', alignItems: 'center', gap: 6, padding: '4px 8px', borderRadius: 6,
                        background: 'rgba(60,240,255,0.03)', border: '1px solid rgba(60,240,255,0.08)',
                      }}>
                        <span style={{ fontSize: '0.7rem' }}>{'\ud83d\udcc4'}</span>
                        <span style={{ flex: 1, fontSize: '0.625rem', color: 'var(--s-text-muted)', fontFamily: 'var(--s-font-mono)' }} className="s-truncate">
                          {fp.split('\\').pop() || fp}
                        </span>
                        <span
                          onClick={(e) => { e.stopPropagation(); setSelectedFiles((prev) => prev.filter((_, idx) => idx !== i)); }}
                          style={{ fontSize: '0.6rem', color: 'var(--s-red)', cursor: 'pointer', fontWeight: 700, padding: '0 4px' }}
                        >
                          {'\u2715'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Password Input */}
                <input
                  className="s-input"
                  type="password"
                  placeholder={'Verschl\u00fcsselungspasswort eingeben...'}
                  value={filePassword}
                  onChange={(e) => setFilePassword(e.target.value)}
                  style={{ fontSize: '0.75rem' }}
                />

                {/* Encrypt Button */}
                <button
                  className="s-btn s-btn-primary"
                  onClick={handleEncryptFiles}
                  disabled={fileProcessing || !selectedFiles.length || !filePassword.trim()}
                  style={{ width: '100%' }}
                >
                  {fileProcessing ? 'Wird verschl\u00fcsselt...' : `\ud83d\udd12 ${selectedFiles.length} Datei(en) verschl\u00fcsseln`}
                </button>
              </div>

              {/* RIGHT: Encrypted Files Vault + Decrypt */}
              <div className="s-card-spacy" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-amber), var(--s-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                    {'Verschl\u00fcsselte Dateien'}
                  </span>
                  <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', background: 'rgba(255,190,61,0.08)', padding: '1px 6px', borderRadius: 4 }}>
                    {encryptedFiles.length}
                  </span>
                  <div className="s-section-divider" style={{ flex: 1 }} />
                  <button className="s-btn s-btn-ghost s-btn-sm" style={{ fontSize: '0.55rem' }} onClick={fetchEncryptedFiles}>
                    {'\u21bb'}
                  </button>
                </div>

                {/* Decrypt Password */}
                <input
                  className="s-input"
                  type="password"
                  placeholder={'Passwort zum Entschl\u00fcsseln eingeben...'}
                  value={decryptPassword}
                  onChange={(e) => setDecryptPassword(e.target.value)}
                  style={{ fontSize: '0.75rem' }}
                />

                {/* Encrypted Files List */}
                {encryptedFiles.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 240, overflowY: 'auto' }}>
                    {encryptedFiles.map((ef, i) => (
                      <div key={i} style={{
                        display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', borderRadius: 8,
                        background: 'rgba(255,190,61,0.03)', border: '1px solid rgba(255,190,61,0.1)',
                      }}>
                        <span style={{ fontSize: '0.8rem' }}>{'\ud83d\udd10'}</span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: '0.675rem', fontWeight: 600, color: 'var(--s-text-muted)' }} className="s-truncate">
                            {ef.name}
                          </div>
                          <div style={{ fontSize: '0.55rem', color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)' }}>
                            {formatFileSize(ef.size)}{' \u00b7 '}{new Date(ef.modified).toLocaleDateString('de-DE')}
                          </div>
                        </div>
                        <button
                          className="s-btn s-btn-ghost s-btn-sm"
                          style={{ fontSize: '0.55rem', padding: '2px 8px', borderColor: 'rgba(60,240,255,0.15)' }}
                          disabled={fileProcessing || !decryptPassword.trim()}
                          onClick={() => handleDecryptFile(ef.path)}
                        >
                          {'\ud83d\udd13 Entschl\u00fcsseln'}
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', padding: '28px 0', color: 'var(--s-text-dim)', fontSize: '0.7rem' }}>
                    <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: 8 }}>{'\ud83d\udd12'}</span>
                    {'Keine verschl\u00fcsselten Dateien vorhanden'}
                    <br />
                    <span style={{ fontSize: '0.6rem' }}>{'Verschl\u00fcsseln Sie links Dateien, um sie hier zu sehen'}</span>
                  </div>
                )}
              </div>
            </div>

            {/* ─── TEXT ENCRYPTION SECTION ─── */}
            <div style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', lineHeight: 1.5, padding: '8px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.02)', border: '1px dashed rgba(109,120,255,0.08)' }}>
              <strong style={{ color: 'var(--s-text-muted)' }}>{'Textverschl\u00fcsselung:'}</strong>{' Geben Sie Text ein und klicken Sie \u201eVerschl\u00fcsseln\u201c \u2014 Sie erhalten einen verschl\u00fcsselten Code. Zum Entschl\u00fcsseln f\u00fcgen Sie diesen Code rechts ein.'}
              {argusOnline ? ' ARGUS (AI-Backend) ist aktiv und wird bevorzugt.' : argusOnline === false ? ' ARGUS ist offline \u2014 lokale AES-256-GCM Verschl\u00fcsselung wird verwendet.' : ''}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <span style={{ fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), var(--s-green))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('vault.encryption.encrypt')}</span>
                <div className="s-section-divider" style={{ flex: 1 }} />
              </div>
              <textarea className="s-input" rows={4} placeholder={t('vault.argusEncryption.dataPlaceholder')} value={plaintext} onChange={(e) => setPlaintext(e.target.value)} style={{ resize: 'vertical', marginBottom: 12 }} />
              <button className="s-btn s-btn-primary" onClick={handleEncrypt} disabled={processing || !plaintext.trim()}>
                {processing ? t('common.loading') : `\ud83d\udd12 ${t('vault.encryption.encrypt')}`}
              </button>
              {encryptResult && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                    {engineBadge(encryptResult.engine)}
                    {encryptResult.engine !== 'error' && (
                      <button className="s-btn s-btn-ghost s-btn-sm" style={{ padding: '1px 6px', fontSize: '0.6rem' }} onClick={() => { navigator.clipboard.writeText(encryptResult.text); }}>{t('common.copy')}</button>
                    )}
                  </div>
                  <div style={{ padding: 12, background: 'rgba(8,8,28,0.4)', borderRadius: 'var(--s-radius-sm)', fontFamily: 'var(--s-font-mono)', fontSize: '0.7rem', wordBreak: 'break-all', color: resultColor(encryptResult.engine), maxHeight: 150, overflowY: 'auto' }}>
                    {encryptResult.text}
                  </div>
                </div>
              )}
            </div>

            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <span style={{ fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-amber), var(--s-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('vault.encryption.decrypt')}</span>
                <div className="s-section-divider" style={{ flex: 1 }} />
              </div>
              <textarea className="s-input" rows={4} placeholder={t('vault.argusEncryption.dataPlaceholder')} value={ciphertext} onChange={(e) => setCiphertext(e.target.value)} style={{ resize: 'vertical', marginBottom: 12 }} />
              <button className="s-btn s-btn-primary" onClick={handleDecrypt} disabled={processing || !ciphertext.trim()}>
                {processing ? t('common.loading') : `\ud83d\udd13 ${t('vault.encryption.decrypt')}`}
              </button>
              {decryptResult && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                    {engineBadge(decryptResult.engine)}
                    {decryptResult.source && decryptResult.source !== 'unknown' && decryptResult.engine === 'error' && (
                      <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>
                        {'Verschl\u00fcsselt mit: '}{decryptResult.source === 'argus' ? 'ARGUS' : 'Lokales AES-256'}
                      </span>
                    )}
                  </div>
                  <div style={{ padding: 12, background: 'rgba(8,8,28,0.4)', borderRadius: 'var(--s-radius-sm)', fontFamily: 'var(--s-font-mono)', fontSize: '0.75rem', wordBreak: 'break-all', color: resultColor(decryptResult.engine), maxHeight: 150, overflowY: 'auto' }}>
                    {decryptResult.text}
                  </div>
                  {decryptResult.hint && (
                    <div style={{ fontSize: '0.7rem', color: 'var(--s-text-muted)', marginTop: 6 }}>
                      {decryptResult.hint}
                    </div>
                  )}
                  {decryptResult.argusOffline && (
                    <button
                      className="s-btn s-btn-primary s-btn-sm"
                      style={{ marginTop: 10 }}
                      onClick={handleStartArgusAndRetry}
                      disabled={processing}
                    >
                      {processing ? t('intel.argus.starting') : `\u25b6 ${t('intel.argus.start')}`}
                    </button>
                  )}
                </div>
              )}
            </div>
            </div>
          </motion.div>
        )}

        {/* ═══ Secure Notes ═══ */}
        {tab === 'notes' && (
          <motion.div key="notes" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Beginner tip */}
            <div style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', lineHeight: 1.5, padding: '8px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.02)', border: '1px dashed rgba(109,120,255,0.08)' }}>
              <strong style={{ color: 'var(--s-text-muted)' }}>Sichere Notizen</strong>{' werden mit AES-256-GCM verschl\u00fcsselt und k\u00f6nnen nur mit Ihrem Passwort ge\u00f6ffnet werden. Ideal f\u00fcr Zugangsdaten, Lizenzschl\u00fcssel oder vertrauliche Informationen. Das Passwort wird '}<strong style={{ color: 'var(--s-text-secondary)' }}>nicht gespeichert</strong>{' \u2014 wenn Sie es vergessen, kann die Notiz nicht wiederhergestellt werden.'}
            </div>
            {/* Create Note */}
            <div className="s-card-spacy">
              <div className="s-heading-md" style={{ marginBottom: 12 }}>{t('vault.notes.create')}</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <input className="s-input" placeholder={t('vault.notes.titlePlaceholder')} value={noteTitle} onChange={(e) => setNoteTitle(e.target.value)} />
                <textarea className="s-input" rows={4} placeholder={t('vault.notes.contentPlaceholder')} value={noteContent} onChange={(e) => setNoteContent(e.target.value)} style={{ resize: 'vertical' }} />
                <input className="s-input" type="password" placeholder={t('vault.encryption.passwordPlaceholder')} value={notePassword} onChange={(e) => setNotePassword(e.target.value)} />
                <button className="s-btn s-btn-primary" onClick={handleSaveNote} disabled={!noteTitle.trim() || !noteContent.trim() || !notePassword.trim()}>
                  🔒 {t('vault.notes.create')}
                </button>
              </div>
            </div>

            {/* Notes List */}
            <div className="s-card-spacy">
              <div className="s-flex-between" style={{ marginBottom: 12 }}>
                <div className="s-heading-md">{t('vault.notes.title')} ({notes.length})</div>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={fetchNotes} disabled={notesLoading}>↻</button>
              </div>
              {notes.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '24px 16px', color: 'var(--s-text-dim)' }}>
                  <div style={{ fontSize: '1.5rem', marginBottom: 8, opacity: 0.3 }}>{"\ud83d\udd10"}</div>
                  <div style={{ fontSize: '0.8125rem', marginBottom: 4 }}>{notesLoading ? t('common.loading') : 'Noch keine Notizen'}</div>
                  <div style={{ fontSize: '0.675rem', maxWidth: 360, margin: '0 auto', lineHeight: 1.5 }}>
                    {'Erstellen Sie oben Ihre erste sichere Notiz. Jede Notiz wird einzeln verschl\u00fcsselt und ist nur mit dem jeweiligen Passwort lesbar.'}
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {notes.map((n) => (
                    <div key={n.id} style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '10px 14px', borderRadius: 'var(--s-radius-sm)',
                      background: openedNote?.id === n.id ? 'rgba(109,120,255,0.08)' : 'rgba(8,8,28,0.3)',
                      border: `1px solid ${openedNote?.id === n.id ? 'rgba(109,120,255,0.2)' : 'var(--s-border)'}`,
                    }}>
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{n.title}</div>
                        <div style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', marginTop: 2 }}>
                          {new Date(n.createdAt).toLocaleString('de-DE')}
                          {n.engine && <span style={{ marginLeft: 8 }} className="s-badge s-badge-cyan">{n.engine}</span>}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button className="s-btn s-btn-ghost s-btn-sm" onClick={async () => {
                          const pw = await showInput({ title: 'Notiz entsperren', message: 'Geben Sie das Passwort ein, um diese verschl\u00fcsselte Notiz zu \u00f6ffnen.', placeholder: 'Passwort\u2026', inputType: 'password', variant: 'info', confirmLabel: '\u00d6ffnen' });
                          if (pw) handleOpenNote(n.id, pw);
                        }}>🔓 Open</button>
                        <button className="s-btn s-btn-danger s-btn-sm" onClick={() => handleDeleteNote(n.id)}>🗑</button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Opened Note Content */}
            {openedNote && (
              <div className="s-card-spacy" style={{ borderColor: 'rgba(109,120,255,0.2)' }}>
                <div className="s-flex-between" style={{ marginBottom: 12 }}>
                  <div className="s-heading-sm">{openedNote.title}</div>
                  <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => setOpenedNote(null)}>Close</button>
                </div>
                <div style={{
                  padding: 16, background: 'rgba(8,8,28,0.5)', borderRadius: 'var(--s-radius-sm)',
                  fontFamily: 'var(--s-font-mono)', fontSize: '0.8125rem', lineHeight: 1.6,
                  color: 'var(--s-cyan)', whiteSpace: 'pre-wrap', maxHeight: 300, overflowY: 'auto',
                }}>
                  {openedNote.content}
                </div>
              </div>
            )}
          </motion.div>
        )}

        {/* ═══ Password Generator ═══ */}
        {tab === 'passwords' && (
          <motion.div key="passwords" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy">
            <div className="s-heading-md" style={{ marginBottom: 8 }}>{t('vault.passwords.title')}</div>
            <div style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', marginBottom: 14, lineHeight: 1.5, padding: '8px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.02)', border: '1px dashed rgba(109,120,255,0.08)' }}>
              <strong style={{ color: 'var(--s-text-muted)' }}>{'Passwort-Tipps:'}</strong>{' Verwenden Sie mindestens '}<strong style={{ color: 'var(--s-text-secondary)' }}>16 Zeichen</strong>{' f\u00fcr wichtige Konten. Der Generator erzeugt kryptografisch sichere Zufallspassw\u00f6rter mit Gro\u00df-/Kleinbuchstaben, Zahlen und Sonderzeichen. Ein 20-Zeichen-Passwort hat ca. 130 Bit Entropie \u2014 praktisch unknackbar. Passw\u00f6rter werden '}<strong style={{ color: 'var(--s-text-secondary)' }}>nicht gespeichert</strong>{', kopieren Sie sie sofort.'}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16 }}>
              <label style={{ fontSize: '0.8125rem', color: 'var(--s-text-secondary)' }}>{'L\u00e4nge:'}</label>
              <input type="range" min={8} max={64} value={pwLength} onChange={(e) => setPwLength(parseInt(e.target.value, 10))} style={{ flex: 1 }} />
              <span style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.875rem', minWidth: 30 }}>{pwLength}</span>
            </div>
            <button className="s-btn s-btn-primary s-btn-lg" onClick={generatePassword} style={{ marginBottom: 16 }}>
              Passwort generieren
            </button>
            {generatedPw && (
              <div style={{ position: 'relative' }}>
                <div style={{
                  padding: 16, background: 'rgba(8,8,28,0.5)', borderRadius: 'var(--s-radius-md)',
                  border: '1px solid var(--s-border)', fontFamily: 'var(--s-font-mono)', fontSize: '1.1rem',
                  letterSpacing: '0.05em', color: 'var(--s-cyan)', wordBreak: 'break-all',
                  textShadow: '0 0 8px rgba(60,240,255,0.3)',
                }}>
                  {generatedPw}
                </div>
                <button
                  className="s-btn s-btn-ghost s-btn-sm"
                  style={{ position: 'absolute', top: 8, right: 8 }}
                  onClick={copyPassword}
                >
                  {pwCopied ? 'Kopiert!' : 'Kopieren'}
                </button>
                <div style={{ marginTop: 8, display: 'flex', gap: 12, alignItems: 'center' }}>
                  <span className="s-badge s-badge-green">{'L\u00e4nge: '}{generatedPw.length}</span>
                  <span className="s-badge s-badge-cyan">{'Entropie: ~'}{Math.round(generatedPw.length * 6.5)}{' Bit'}</span>
                  {/* Strength indicator */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ fontSize: '0.55rem', color: 'var(--s-text-dim)' }}>{'St\u00e4rke:'}</span>
                    {[1,2,3,4,5].map(i => (
                      <div key={i} style={{ width: 10, height: 5, borderRadius: 2, background: generatedPw.length >= i * 8 ? (generatedPw.length >= 20 ? 'var(--s-green)' : generatedPw.length >= 12 ? 'var(--s-amber)' : 'var(--s-red)') : 'rgba(109,120,255,0.1)' }} />
                    ))}
                    <span style={{ fontSize: '0.55rem', fontWeight: 700, color: generatedPw.length >= 20 ? 'var(--s-green)' : generatedPw.length >= 12 ? 'var(--s-amber)' : 'var(--s-red)' }}>
                      {generatedPw.length >= 20 ? 'STARK' : generatedPw.length >= 12 ? 'MITTEL' : 'SCHWACH'}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </motion.div>
        )}

        {/* ═══ File Shredder ═══ */}
        {tab === 'shredder' && (
          <motion.div key="shredder" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <div className="s-heading-md">{t('vault.shredder.title')}</div>
                <InfoBadge glossaryKey="DSGVO Art.17" />
                <InfoBadge glossaryKey="LOKAL" />
              </div>
              <div style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)', marginBottom: 8, lineHeight: 1.6 }}>
                {'Dateien unwiderruflich vernichten durch mehrfaches \u00dcberschreiben. Geschredderte Dateien k\u00f6nnen mit keinem Datenrettungstool wiederhergestellt werden.'}
              </div>
              <div style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', marginBottom: 16, lineHeight: 1.5, padding: '8px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.02)', border: '1px dashed rgba(109,120,255,0.08)' }}>
                <strong style={{ color: 'var(--s-text-muted)' }}>{'F\u00fcr Einsteiger:'}</strong>{' Normales L\u00f6schen entfernt nur den Verzeichniseintrag \u2014 die Daten bleiben auf der Festplatte und k\u00f6nnen wiederhergestellt werden. Der Shredder \u00fcberschreibt den Speicherbereich mehrfach mit Zufallsdaten, was eine Wiederherstellung unm\u00f6glich macht. Ideal f\u00fcr vertrauliche Dokumente gem\u00e4\u00df DSGVO Art.17 (Recht auf L\u00f6schung).'}
              </div>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 16 }}>
                <button className="s-btn s-btn-danger" onClick={async () => {
                  try {
                    const input = document.createElement('input');
                    input.type = 'file';
                    input.multiple = true;
                    input.onchange = async () => {
                      if (!input.files?.length) return;
                      const paths = Array.from(input.files).map(f => (f as any).path || f.name);
                      if (!paths.length) return;
                      const r = await api()?.vault?.shredFiles?.(paths);
                      if (r?.success) { notify.success(r.message || `Shredded ${paths.length} file(s)`); fetchShredStats(); }
                      else notify.error(r?.error || 'Shred failed');
                    };
                    input.click();
                  } catch (e: any) { notify.error(e?.message || 'Shred failed'); }
                }}>
                  🔥 Select Files to Shred
                </button>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={fetchShredStats}>↻ Refresh Stats</button>
              </div>
              {shredStats && (
                <div style={{ display: 'flex', gap: 16 }}>
                  <div style={{ padding: '10px 16px', borderRadius: 'var(--s-radius-sm)', background: 'rgba(255,95,95,0.06)', border: '1px solid rgba(255,95,95,0.15)' }}>
                    <div style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--s-font-display)', color: 'var(--s-red)' }}>{shredStats.totalShredded}</div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', textTransform: 'uppercase' }}>Files Shredded</div>
                  </div>
                  <div style={{ padding: '10px 16px', borderRadius: 'var(--s-radius-sm)', background: 'rgba(109,120,255,0.06)', border: '1px solid rgba(109,120,255,0.15)' }}>
                    <div style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--s-font-display)', color: 'var(--s-cyan)' }}>{(shredStats.totalBytes / (1024 * 1024)).toFixed(1)} MB</div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--s-text-dim)', textTransform: 'uppercase' }}>Data Destroyed</div>
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* ═══ Whitelist Config ═══ */}
        {tab === 'config' && (
          <motion.div key="config" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* PIN Lock / Zero-Trust Auth */}
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                <span style={{ fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), var(--s-purple))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Vault-Authentifizierung</span>
                <InfoBadge glossaryKey="DSGVO Art.32" />
                <InfoBadge glossaryKey="OSOP" />
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', marginBottom: 6, lineHeight: 1.6 }}>
                Phishing-resistente lokale PIN-Sperre {'\u2014'} bei jedem Start erforderlich. 30 Minuten Sitzungsdauer, danach erneute Eingabe n{'\u00f6'}tig.
              </div>
              <div style={{ fontSize: '0.675rem', color: 'var(--s-text-dim)', marginBottom: 14, lineHeight: 1.5, padding: '8px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.02)', border: '1px dashed rgba(109,120,255,0.08)' }}>
                <strong style={{ color: 'var(--s-text-muted)' }}>Was bedeutet das?</strong> Wenn Sie eine PIN setzen, m{'\u00fc'}ssen Sie diese bei jedem Start von Sentinel eingeben, bevor Sie auf verschl{'\u00fc'}sselte Daten zugreifen k{'\u00f6'}nnen. Die PIN wird <strong style={{ color: 'var(--s-text-secondary)' }}>niemals im Klartext</strong> gespeichert {'\u2014'} nur ein kryptografischer Hash (PBKDF2). Dies sch{'\u00fc'}tzt Ihren Vault gem{'\u00e4'}{'\u00df'} DSGVO Art.32 (Sicherheit der Verarbeitung) vor unbefugtem Zugriff. Die Sitzung l{'\u00e4'}uft nach 30 Minuten Inaktivit{'\u00e4'}t automatisch ab.
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button className="s-btn s-btn-sm s-btn-primary" onClick={async () => {
                  try {
                    const status = await api()?.auth?.getStatus?.();
                    if (status?.hasPin) {
                      const pin = await showInput({ title: 'PIN entfernen', message: 'Geben Sie Ihre aktuelle PIN ein, um die Sperre zu entfernen.', placeholder: 'Aktuelle PIN eingeben\u2026', inputType: 'password', variant: 'warning', confirmLabel: 'PIN entfernen' });
                      if (pin) {
                        const r = await api()?.auth?.removePin?.(pin);
                        if (r?.success) notify.success('PIN-Sperre entfernt');
                        else notify.error(r?.error || 'Fehlgeschlagen');
                      }
                    } else {
                      const pin = await showInput({ title: 'PIN festlegen', message: 'Legen Sie eine PIN fest (mindestens 4 Zeichen). Diese wird bei jedem Start von Sentinel abgefragt.', placeholder: 'Neue PIN eingeben (min. 4 Zeichen)\u2026', inputType: 'password', variant: 'info', confirmLabel: 'PIN aktivieren' });
                      if (pin) {
                        const r = await api()?.auth?.setPin?.(pin);
                        if (r?.success) notify.success('PIN-Sperre aktiviert \u2014 bei jedem Start erforderlich');
                        else notify.error(r?.error || 'Fehlgeschlagen');
                      }
                    }
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}>PIN festlegen / entfernen</button>
                <button className="s-btn s-btn-sm s-btn-ghost" onClick={async () => {
                  try {
                    await api()?.auth?.lock?.();
                    notify.info('Session locked — re-authenticate to continue');
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}>Lock Now</button>
                <button className="s-btn s-btn-sm s-btn-ghost" onClick={async () => {
                  try {
                    const s = await api()?.auth?.getStatus?.();
                    notify.info(`PIN: ${s?.hasPin ? 'Set' : 'Not set'} | Session: ${s?.sessionValid ? 'Active' : 'Expired'} | Require on Launch: ${s?.requireOnLaunch ? 'Yes' : 'No'}`);
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}>Auth Status</button>
              </div>
            </div>

            {/* TOTP Multi-Factor Authentication */}
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                <span style={{ fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-green), var(--s-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>TOTP Multi-Faktor-Authentifizierung</span>
                <InfoBadge glossaryKey="TOTP" />
                <InfoBadge glossaryKey="DSGVO Art.32" />
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', marginBottom: 6, lineHeight: 1.6 }}>
                Zeitbasierte Einmalpassw{'\u00f6'}rter (TOTP) als zweiter Faktor neben der PIN. Kompatibel mit Google Authenticator, Authy, Microsoft Authenticator und allen TOTP-Apps.
              </div>
              <div style={{ fontSize: '0.675rem', color: 'var(--s-text-dim)', marginBottom: 14, lineHeight: 1.5, padding: '8px 12px', borderRadius: 8, background: 'rgba(109,120,255,0.02)', border: '1px dashed rgba(109,120,255,0.08)' }}>
                <strong style={{ color: 'var(--s-text-muted)' }}>F{'\u00fc'}r Einsteiger:</strong> TOTP erzeugt alle 30 Sekunden einen neuen 6-stelligen Code in Ihrer Authenticator-App. Selbst wenn jemand Ihre PIN kennt, kann er ohne Ihr Smartphone nicht auf den Vault zugreifen. Die Einrichtung dauert nur 30 Sekunden: Secret abfotografieren und Code best{'\u00e4'}tigen.
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button className="s-btn s-btn-sm s-btn-primary" onClick={async () => {
                  try {
                    const status = await api()?.totp?.getStatus?.();
                    if (status?.enabled) {
                      const code = await showInput({ title: 'TOTP deaktivieren', message: 'Geben Sie Ihren aktuellen Authenticator-Code ein, um die Zwei-Faktor-Authentifizierung zu deaktivieren.', placeholder: '6-stelliger Code\u2026', variant: 'warning', confirmLabel: 'MFA deaktivieren' });
                      if (code) {
                        const r = await api()?.totp?.disable?.(code);
                        if (r?.success) notify.success('TOTP-MFA deaktiviert');
                        else notify.error(r?.error || 'Deaktivierung fehlgeschlagen');
                      }
                    } else {
                      const r = await api()?.totp?.setup?.();
                      if (r?.success && r.secret) {
                        const code = await showInput({ title: 'TOTP einrichten', message: `Geben Sie dieses Secret in Ihre Authenticator-App ein:\n\n${r.secret}\n\nBest\u00e4tigen Sie mit dem generierten 6-stelligen Code.`, placeholder: '6-stelliger Code aus der App\u2026', variant: 'info', confirmLabel: 'Code best\u00e4tigen' });
                        if (code) {
                          const v = await api()?.totp?.verifyAndEnable?.(code);
                          if (v?.success) {
                            const backupMsg = v.backupCodes ? `TOTP erfolgreich aktiviert!\n\nSichern Sie diese Backup-Codes an einem sicheren Ort:\n\n${v.backupCodes.join('\n')}\n\nJeder Code kann nur einmal verwendet werden.` : 'TOTP erfolgreich aktiviert!';
                            await showAlert({ title: 'Backup-Codes sichern', message: backupMsg, variant: 'success' });
                            notify.success('TOTP-MFA aktiviert \u2014 Backup-Codes gesichert!');
                          } else { notify.error(v?.error || 'Code ung\u00fcltig'); }
                        }
                      } else { notify.error(r?.error || 'Setup fehlgeschlagen'); }
                    }
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}>TOTP Ein/Aus</button>
                <button className="s-btn s-btn-sm s-btn-ghost" onClick={async () => {
                  try {
                    const s = await api()?.totp?.getStatus?.();
                    notify.info(`TOTP: ${s?.enabled ? 'Aktiv' : 'Inaktiv'} | Konfiguriert: ${s?.configured ? 'Ja' : 'Nein'} | Backup-Codes: ${s?.backupCodesRemaining ?? 0} verbleibend`);
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}>MFA Status</button>
                <button className="s-btn s-btn-sm s-btn-ghost" onClick={async () => {
                  try {
                    const code = await showInput({ title: 'Code pr\u00fcfen', message: 'Geben Sie einen TOTP-Code oder Backup-Code ein, um die Verifizierung zu testen.', placeholder: '6-stelliger Code oder Backup-Code\u2026', variant: 'info', confirmLabel: 'Pr\u00fcfen' });
                    if (code) {
                      const r = await api()?.totp?.verify?.(code);
                      if (r?.success) notify.success(`Verifiziert (${r.method === 'backup' ? 'Backup-Code' : 'TOTP-Code'})`);
                      else notify.error(r?.error || 'Code ung\u00fcltig');
                    }
                  } catch (e: any) { notify.error(e?.message || 'Error'); }
                }}>Code pr{'\u00fc'}fen</button>
              </div>
            </div>

            {/* ARGUS Connection Status */}
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                <span style={{ fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), var(--s-green))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>ARGUS-Backend Status</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', borderRadius: 8, background: argusOnline ? 'rgba(61,255,143,0.04)' : 'rgba(255,100,100,0.04)', border: `1px solid ${argusOnline ? 'rgba(61,255,143,0.15)' : 'rgba(255,100,100,0.15)'}` }}>
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: argusOnline ? 'var(--s-green)' : 'var(--s-red)', boxShadow: argusOnline ? '0 0 8px rgba(61,255,143,0.5)' : '0 0 8px rgba(255,100,100,0.5)' }} />
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: argusOnline ? 'var(--s-green)' : 'var(--s-red)' }}>
                  {argusOnline ? 'ARGUS online \u2014 KI-gest\u00fctzte Verschl\u00fcsselung verf\u00fcgbar' : 'ARGUS offline \u2014 lokale AES-256-GCM Verschl\u00fcsselung aktiv'}
                </span>
              </div>
              <div style={{ fontSize: '0.625rem', color: 'var(--s-text-dim)', marginTop: 8, lineHeight: 1.5 }}>
                {'Bei aktiver ARGUS-Verbindung wird die Textverschl\u00fcsselung \u00fcber das KI-Backend durchgef\u00fchrt. Die Dateiverschl\u00fcsselung verwendet immer lokales AES-256-GCM mit PBKDF2-Schl\u00fcsselableitung.'}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      <InputModal {...modalProps} />
    </div>
  );
};

export default VaultPage;
