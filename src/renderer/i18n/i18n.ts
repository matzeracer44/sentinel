import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

const resources = {
  en: {
    translation: {
      navigation: {
        dashboard: 'Dashboard',
        shield: 'Shield',
        ghost: 'Ghost',
        forge: 'Forge',
        vault: 'Vault',
        settings: 'Settings',
      },
      admin: {
        title: 'Admin Mode',
        limited: 'Limited Mode',
        banner: 'Some features require administrator privileges. Restart the app as admin for full functionality.',
      },
    },
  },
  de: {
    translation: {
      navigation: {
        dashboard: 'Dashboard',
        shield: 'Schild',
        ghost: 'Geist',
        forge: 'Schmiede',
        vault: 'Tresor',
        settings: 'Einstellungen',
      },
      admin: {
        title: 'Admin-Modus',
        limited: 'Eingeschränkter Modus',
        banner: 'Einige Funktionen erfordern Administratorrechte. Starten Sie die App als Administrator neu für volle Funktionalität.',
      },
    },
  },
};

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false,
    },
  });

export default i18n;
