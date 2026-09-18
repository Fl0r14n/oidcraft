import CircularProgress from '@mui/material/CircularProgress'
import Stack from '@mui/material/Stack'
import { useEffect } from 'react'
import { useOAuth } from 'react-oauth-oidc'
import { useNavigate, useSearchParams } from 'react-router'

/** An effect rather than a route loader: the exchange needs the `code_verifier` from browser storage,
 * and a loader also runs on the server — where an exchange without the verifier would still burn the
 * single-use code at the IdP, leaving the browser's own exchange to fail with `invalid_grant`.
 *
 * No guard against a second invocation: `oauthCallback` is idempotent per redirect, so StrictMode's
 * double-invoke and a Back into this URL both resolve to the first exchange. */
export const OAuthCallbackPage = () => {
  const { oauthCallback } = useOAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  useEffect(() => {
    const returnUrl = searchParams.get('returnUrl')
    void oauthCallback(globalThis.location?.href).finally(() => navigate(returnUrl || '/', { replace: true }))
  }, [oauthCallback, navigate, searchParams])

  return (
    <Stack sx={{ minHeight: '50vh', alignItems: 'center', justifyContent: 'center' }}>
      <CircularProgress />
    </Stack>
  )
}

export default OAuthCallbackPage
