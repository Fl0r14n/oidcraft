import AccountCircle from '@mui/icons-material/AccountCircle'
import AccountCircleOutlined from '@mui/icons-material/AccountCircleOutlined'
import EmailOutlined from '@mui/icons-material/EmailOutlined'
import LockOutlined from '@mui/icons-material/LockOutlined'
import Login from '@mui/icons-material/Login'
import Logout from '@mui/icons-material/Logout'
import Visibility from '@mui/icons-material/Visibility'
import VisibilityOff from '@mui/icons-material/VisibilityOff'
import Alert from '@mui/material/Alert'
import Avatar from '@mui/material/Avatar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardActions from '@mui/material/CardActions'
import CardContent from '@mui/material/CardContent'
import IconButton from '@mui/material/IconButton'
import InputAdornment from '@mui/material/InputAdornment'
import List from '@mui/material/List'
import ListItem from '@mui/material/ListItem'
import ListItemAvatar from '@mui/material/ListItemAvatar'
import ListItemText from '@mui/material/ListItemText'
import Menu from '@mui/material/Menu'
import TextField from '@mui/material/TextField'
import { type ReactNode, type SyntheticEvent, useState } from 'react'
// by package name, never a relative path: this entry is bundled separately, so a relative import inlines a
// second copy of the core — a second React context — and the component goes blind to the app's instance
import {
  type AuthorizationCodeParameters,
  type OAuthFieldError,
  type OAuthParameters,
  OAuthType,
  type ResourceOwnerParameters,
  type UserInfo,
  useAuth,
  useIsAuthorized,
  useOAuthActions,
  useOAuthForm
} from 'react-oauth-oidc'

/** Every string the component renders. Pass your own to translate — the library carries no i18n dep. */
export interface OAuthLabels {
  login: string
  logout: string
  username: string
  password: string
  usernameRequired: string
  passwordRequired: string
  /** `{0}` is replaced with the max length */
  usernameLength: string
  passwordLength: string
  account: string
}

export const defaultOAuthLabels: OAuthLabels = {
  login: 'Login',
  logout: 'Logout',
  username: 'Username',
  password: 'Password',
  usernameRequired: 'Name is required',
  passwordRequired: 'Password is required',
  usernameLength: 'Name must be less than {0} characters',
  passwordLength: 'Password must be less than {0} characters',
  account: 'Account'
}

export type OAuthProps = Partial<ResourceOwnerParameters & AuthorizationCodeParameters & { logoutRedirectUri: string }> & {
  labels?: Partial<OAuthLabels>
  /** replaces the default user row with your own; gets the user and a ready-to-call logout */
  renderUserInfo?: (props: { user?: UserInfo | undefined; logout: () => void }) => ReactNode
}

const interpolate = (template: string, value: unknown) => template.replace('{0}', String(value))

/** `useOAuthForm` reports error codes, not sentences — this is where they become words. */
const messageFor = (error: OAuthFieldError, required: string, tooLong: string, maxLength: number) =>
  (error === 'required' && required) || (error === 'tooLong' && interpolate(tooLong, maxLength)) || ''

const initialsOf = (user?: UserInfo) => {
  const { given_name, family_name } = user || {}
  return `${given_name?.charAt(0) || ''}${family_name?.charAt(0) || ''}` || '?'
}

/** Falls back to the generic label so the row is never blank — some providers return only a `sub`. */
const displayName = (user: UserInfo | undefined, fallback: string) =>
  user?.name || user?.email || user?.preferred_username || user?.sub || fallback

/** Account menu: the user's row when signed in, otherwise the login affordance for the configured grant —
 * one button for the redirect flows, a username/password form for the resource-owner grant.
 *
 * Server-renders the signed-out view, since the token comes from `localStorage`. The hooks report
 * signed-out during hydration too, then re-render — no mount gate, markup present from the first paint. */
export const OAuth = ({ labels, renderUserInfo, logoutRedirectUri, username, password, ...parameters }: OAuthProps) => {
  const t = { ...defaultOAuthLabels, ...labels }
  const isAuthorized = useIsAuthorized()
  const { login, logout } = useOAuthActions()
  const { user } = useAuth()
  const form = useOAuthForm({ username, password })

  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null)

  const close = () => setAnchorEl(null)

  const signOut = async () => {
    close()
    await logout(logoutRedirectUri)
  }

  const { responseType } = parameters
  const isRedirectFlow = !!responseType && responseType !== OAuthType.RESOURCE

  return (
    <>
      <IconButton color="inherit" aria-label={t.account} onClick={event => setAnchorEl(event.currentTarget)}>
        {isAuthorized ? <AccountCircle /> : <AccountCircleOutlined />}
      </IconButton>
      <Menu
        open={!!anchorEl}
        anchorEl={anchorEl}
        onClose={close}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
        slotProps={{ list: { sx: { py: 0 } } }}>
        {/* a Card inside the Menu, not MenuItems: the content is a form and a user card, neither of
            which should close the menu or take keyboard focus as a list option */}
        {/* no width here: only the credentials form needs a floor, and putting it on the Card stretched
            the single-button and error views to match */}
        <Card elevation={0}>
          {isAuthorized ? (
            renderUserInfo ? (
              renderUserInfo({ user, logout: () => void signOut() })
            ) : (
              // unconditional: logout lives in this row, so skipping it for a user with no name or
              // email would leave no way to sign out
              <List>
                <ListItem
                  secondaryAction={
                    <IconButton edge="end" aria-label={t.logout} title={t.logout} onClick={() => void signOut()}>
                      <Logout />
                    </IconButton>
                  }>
                  <ListItemAvatar>
                    <Avatar sx={{ bgcolor: 'primary.main' }} src={user?.picture} alt={displayName(user, t.account)}>
                      {!user?.picture && initialsOf(user)}
                    </Avatar>
                  </ListItemAvatar>
                  {/* the email only repeats as the secondary line when it is not already the primary one */}
                  <ListItemText primary={displayName(user, t.account)} secondary={user?.name ? user.email : undefined} />
                </ListItem>
              </List>
            )
          ) : form.error ? (
            <CardContent>
              <Alert severity="error" variant="outlined" onClose={form.dismissError}>
                {form.error}
              </Alert>
            </CardContent>
          ) : isRedirectFlow ? (
            <CardActions sx={{ justifyContent: 'flex-end' }}>
              <Button color="inherit" startIcon={<Login />} onClick={() => void login(parameters as OAuthParameters)}>
                {t.login}
              </Button>
            </CardActions>
          ) : (
            <Box
              component="form"
              autoComplete="on"
              onSubmit={(event: SyntheticEvent) => void form.submit(event)}
              noValidate
              sx={{ minWidth: 300 }}>
              <CardContent sx={{ pb: 0, display: 'grid', gap: 2 }}>
                <TextField
                  name="username"
                  size="small"
                  required
                  autoComplete="username"
                  label={t.username}
                  value={form.username.value}
                  error={form.username.showError}
                  helperText={
                    (form.username.showError && messageFor(form.username.error, t.usernameRequired, t.usernameLength, form.maxLength)) ||
                    ' '
                  }
                  onChange={e => form.username.onChange(e.target.value)}
                  slotProps={{
                    input: {
                      startAdornment: (
                        <InputAdornment position="start">
                          <EmailOutlined fontSize="small" />
                        </InputAdornment>
                      )
                    }
                  }}
                />
                <TextField
                  name="password"
                  size="small"
                  required
                  autoComplete="current-password"
                  type={form.passwordVisible ? 'text' : 'password'}
                  label={t.password}
                  value={form.password.value}
                  error={form.password.showError}
                  helperText={
                    (form.password.showError && messageFor(form.password.error, t.passwordRequired, t.passwordLength, form.maxLength)) ||
                    ' '
                  }
                  onChange={e => form.password.onChange(e.target.value)}
                  slotProps={{
                    input: {
                      startAdornment: (
                        <InputAdornment position="start">
                          <LockOutlined fontSize="small" />
                        </InputAdornment>
                      ),
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton
                            edge="end"
                            size="small"
                            tabIndex={-1}
                            aria-label={form.passwordVisible ? 'hide password' : 'show password'}
                            onClick={form.togglePasswordVisible}>
                            {form.passwordVisible ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                          </IconButton>
                        </InputAdornment>
                      )
                    }
                  }}
                />
              </CardContent>
              <CardActions sx={{ justifyContent: 'flex-end' }}>
                <Button type="submit" color="inherit" startIcon={<Login />} disabled={(form.submitted && !form.valid) || form.submitting}>
                  {t.login}
                </Button>
              </CardActions>
            </Box>
          )}
        </Card>
      </Menu>
    </>
  )
}

export default OAuth
