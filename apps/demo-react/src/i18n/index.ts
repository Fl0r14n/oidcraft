import { createInstance, type i18n } from 'i18next'
import { initReactI18next } from 'react-i18next'
import { de } from './de'
import { en } from './en'

export type { Translation } from './en'
export { de, en }

/** One per app instance — a singleton would leak one request's locale into another during concurrent
 * SSR. `{0}` interpolation matches the OAuth component's length messages. */
export const createI18n = (locale = 'en'): i18n => {
  const instance = createInstance()
  instance.use(initReactI18next).init({
    lng: locale,
    fallbackLng: 'en',
    resources: {
      en: { translation: en },
      de: { translation: de }
    },
    interpolation: { escapeValue: false, prefix: '{', suffix: '}' }
  })
  return instance
}
