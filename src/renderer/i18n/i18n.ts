import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import en from './en';
import de from './de';

const resources = {
  en: { translation: en },
  de: { translation: de },
};

// Persist language choice in localStorage
const savedLang = typeof localStorage !== 'undefined'
  ? localStorage.getItem('sentinel-language') || 'de'
  : 'de';

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: savedLang,
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false,
    },
  });

// Persist on language change
i18n.on('languageChanged', (lng: string) => {
  try { localStorage.setItem('sentinel-language', lng); } catch { /* storage may be unavailable */ }
});

export default i18n;
