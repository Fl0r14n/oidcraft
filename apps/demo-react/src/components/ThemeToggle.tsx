import DarkMode from '@mui/icons-material/DarkMode'
import LightMode from '@mui/icons-material/LightMode'
import IconButton from '@mui/material/IconButton'
import { useTranslation } from 'react-i18next'
import { useColorMode } from '../app'

export const ThemeToggle = () => {
  const { mode, setMode } = useColorMode()
  const { t } = useTranslation()
  const next = mode === 'light' ? 'dark' : 'light'

  return (
    <IconButton color="inherit" aria-label={t(`theme.${next}`)} title={t(`theme.${next}`)} onClick={() => setMode(next)}>
      {mode === 'light' ? <DarkMode /> : <LightMode />}
    </IconButton>
  )
}

export default ThemeToggle
