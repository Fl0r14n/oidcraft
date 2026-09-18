import { Navigate, type RouteObject } from 'react-router'
import MainPage from './pages/MainPage'
import OAuthCallbackPage from './pages/OAuthCallbackPage'

export const routes: RouteObject[] = [
  { path: '/', element: <MainPage /> },
  { path: '/oauth_callback', element: <OAuthCallbackPage /> },
  { path: '*', element: <Navigate to="/" replace /> }
]
