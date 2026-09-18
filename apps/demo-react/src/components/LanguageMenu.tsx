import Language from '@mui/icons-material/Language'
import IconButton from '@mui/material/IconButton'
import Menu from '@mui/material/Menu'
import MenuItem from '@mui/material/MenuItem'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

const LANGUAGES = [
  { code: 'en', label: 'English' },
  { code: 'de', label: 'Deutsch' }
]

export const LanguageMenu = () => {
  const { t, i18n } = useTranslation()
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null)

  const select = (code: string) => {
    void i18n.changeLanguage(code)
    setAnchorEl(null)
  }

  return (
    <>
      <IconButton color="inherit" aria-label={t('language')} title={t('language')} onClick={event => setAnchorEl(event.currentTarget)}>
        <Language />
      </IconButton>
      <Menu open={!!anchorEl} anchorEl={anchorEl} onClose={() => setAnchorEl(null)}>
        {LANGUAGES.map(({ code, label }) => (
          <MenuItem key={code} selected={i18n.resolvedLanguage === code} onClick={() => select(code)}>
            {label}
          </MenuItem>
        ))}
      </Menu>
    </>
  )
}

export default LanguageMenu
