import { createTheme } from '@mui/material/styles'

export const createAppTheme = (mode: 'light' | 'dark' = 'light') =>
  createTheme({
    palette: { mode },
    components: {
      MuiButton: { defaultProps: { variant: 'text' } },
      MuiTextField: { defaultProps: { size: 'small' } },
      MuiAlert: { defaultProps: { variant: 'outlined' } }
    }
  })
