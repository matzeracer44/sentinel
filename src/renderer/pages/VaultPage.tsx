/**
 * SENTINEL UNIFIED — Vault Page
 * Encryption/decryption with ARGUS + local fallback, ARGUS health indicator,
 * secure notes, password generator, whitelist config.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
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
  const [generatedPw, setGeneratedPw] = useState('');
  const [pwLength, setPwLength] = useState(24);
  const [pwCopied, setPwCopied] = useState(false);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [newWhitelistIp, setNewWhitelistIp] = useState('');

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
        notify.success('Note saved securely');
        setNoteTitle(''); setNoteContent(''); setNotePassword('');
        fetchNotes();
      } else { notify.error(r?.error || 'Failed to save note'); }
    } catch (e: any) { notify.error(e?.message || 'Failed to save note'); }
  };

  const handleOpenNote = async (noteId: string, password: string) => {
    try {
      const r = await api()?.vault?.openSecureNote?.(noteId, password);
      if (r?.success && r.note) {
        setOpenedNote({ id: noteId, title: r.note.title || '', content: r.note.content || '' });
      } else { notify.error(r?.error || 'Wrong password or note corrupted'); }
    } catch (e: any) { notify.error(e?.message || 'Failed to open note'); }
  };

  const handleDeleteNote = async (noteId: string) => {
    try {
      const r = await api()?.vault?.deleteSecureNote?.(noteId);
      if (r?.success) { notify.success('Note deleted'); fetchNotes(); setOpenedNote(null); }
      else notify.error(r?.error || 'Delete failed');
    } catch (e: any) { notify.error(e?.message || 'Delete failed'); }
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
          ARGUS backend is offline. Vault will use local AES-256-GCM encryption. Data encrypted locally cannot be decrypted by ARGUS and vice versa.
        </div>
      )}

      <AnimatePresence mode="wait">
        {/* ═══ Encrypt / Decrypt ═══ */}
        {tab === 'encrypt' && (
          <motion.div key="encrypt" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            <div className="s-card-spacy">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <span style={{ fontWeight: 700, fontSize: '0.9rem', fontFamily: 'var(--s-font-display)', background: 'linear-gradient(90deg, var(--s-cyan), var(--s-green))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>{t('vault.encryption.encrypt')}</span>
                <div className="s-section-divider" style={{ flex: 1 }} />
              </div>
              <textarea className="s-input" rows={5} placeholder={t('vault.argusEncryption.dataPlaceholder')} value={plaintext} onChange={(e) => setPlaintext(e.target.value)} style={{ resize: 'vertical', marginBottom: 12 }} />
              <button className="s-btn s-btn-primary" onClick={handleEncrypt} disabled={processing || !plaintext.trim()}>
                {processing ? t('common.loading') : `🔒 ${t('vault.encryption.encrypt')}`}
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
              <textarea className="s-input" rows={5} placeholder={t('vault.argusEncryption.dataPlaceholder')} value={ciphertext} onChange={(e) => setCiphertext(e.target.value)} style={{ resize: 'vertical', marginBottom: 12 }} />
              <button className="s-btn s-btn-primary" onClick={handleDecrypt} disabled={processing || !ciphertext.trim()}>
                {processing ? t('common.loading') : `🔓 ${t('vault.encryption.decrypt')}`}
              </button>
              {decryptResult && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                    {engineBadge(decryptResult.engine)}
                    {decryptResult.source && decryptResult.source !== 'unknown' && decryptResult.engine === 'error' && (
                      <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>
                        Encrypted by: {decryptResult.source === 'argus' ? 'ARGUS' : 'Local AES-256'}
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
                      {processing ? t('intel.argus.starting') : `▶ ${t('intel.argus.start')}`}
                    </button>
                  )}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* ═══ Secure Notes ═══ */}
        {tab === 'notes' && (
          <motion.div key="notes" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
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
                <div style={{ textAlign: 'center', padding: 32, color: 'var(--s-text-dim)' }}>
                  {notesLoading ? t('common.loading') : t('vault.notes.noNotes')}
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
                        <button className="s-btn s-btn-ghost s-btn-sm" onClick={() => {
                          const pw = prompt('Enter password to unlock this note:');
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
            <div className="s-heading-md" style={{ marginBottom: 16 }}>{t('vault.passwords.title')}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16 }}>
              <label style={{ fontSize: '0.8125rem', color: 'var(--s-text-secondary)' }}>Length:</label>
              <input type="range" min={8} max={64} value={pwLength} onChange={(e) => setPwLength(parseInt(e.target.value, 10))} style={{ flex: 1 }} />
              <span style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.875rem', minWidth: 30 }}>{pwLength}</span>
            </div>
            <button className="s-btn s-btn-primary s-btn-lg" onClick={generatePassword} style={{ marginBottom: 16 }}>
              Generate Password
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
                  {pwCopied ? 'Copied!' : 'Copy'}
                </button>
                <div style={{ marginTop: 8, display: 'flex', gap: 12 }}>
                  <span className="s-badge s-badge-green">Length: {generatedPw.length}</span>
                  <span className="s-badge s-badge-cyan">Entropy: ~{Math.round(generatedPw.length * 6.5)} bits</span>
                </div>
              </div>
            )}
          </motion.div>
        )}

        {/* ═══ File Shredder ═══ */}
        {tab === 'shredder' && (
          <motion.div key="shredder" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="s-card-spacy">
              <div className="s-heading-md" style={{ marginBottom: 12 }}>{t('vault.shredder.title')}</div>
              <div style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)', marginBottom: 16, lineHeight: 1.6 }}>
                Permanently destroy files with multi-pass overwrite. Shredded files cannot be recovered by any data recovery tool.
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
          <motion.div key="config" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy">
            <div className="s-heading-md" style={{ marginBottom: 16 }}>{t('vault.argusEncryption.title')}</div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
              <input className="s-input" placeholder="IP address to whitelist" value={newWhitelistIp} onChange={(e) => setNewWhitelistIp(e.target.value)} style={{ maxWidth: 300 }} />
              <button className="s-btn s-btn-primary s-btn-sm" onClick={async () => {
                if (!newWhitelistIp.trim()) return;
                await api()?.sentinelConfig?.addWhitelist?.(newWhitelistIp.trim());
                setNewWhitelistIp('');
                fetchConfig();
              }}>Add</button>
            </div>
            {whitelist.length === 0 ? (
              <div style={{ color: 'var(--s-text-dim)', fontSize: '0.8125rem' }}>No whitelisted IPs</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {whitelist.map((ip, i) => (
                  <div key={`wl-${i}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(109,120,255,0.06)' }}>
                    <span style={{ fontFamily: 'var(--s-font-mono)', fontSize: '0.8125rem' }}>{ip}</span>
                    <button className="s-btn s-btn-danger s-btn-sm" onClick={async () => {
                      await api()?.sentinelConfig?.removeWhitelist?.(ip);
                      fetchConfig();
                    }}>Remove</button>
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default VaultPage;
