import { JsonPipe } from '@angular/common'
import { Component, inject } from '@angular/core'
import { OAUTH } from 'ngx-oauth'

/**
 * Written against the `OAUTH` token rather than against `ngx-oauth/component`, which v9 does not
 * ship (PLAN.md). That makes this the better demo anyway: the signals below are the whole public
 * surface, and a host is expected to bring its own markup.
 */
@Component({
  selector: 'app-main-page',
  imports: [JsonPipe],
  template: `
    <main>
      <h1>ngx-oauth</h1>
      @if (oauth.isAuthorized()) {
        <p>Signed in as {{ oauth.user()?.name ?? oauth.user()?.email ?? oauth.user()?.sub }}</p>
        <pre>{{ oauth.user() | json }}</pre>
        <button type="button" (click)="signOut()">Sign out</button>
      } @else {
        <button type="button" (click)="signIn()">Sign in</button>
      }
      @if (oauth.hasError()) {
        <p role="alert">{{ oauth.error() }}: {{ oauth.errorDescription() }}</p>
      }
    </main>
  `
})
export class MainPage {
  readonly oauth = inject(OAUTH)

  private readonly origin = globalThis.location?.origin ?? 'http://localhost:3003'

  signIn() {
    // `code` only: OAuth 2.1 removed the implicit and hybrid response types (FR-C1)
    void this.oauth.login({
      redirectUri: `${this.origin}/oauth_callback`,
      responseType: 'code',
      accessType: 'offline'
    })
  }

  signOut() {
    void this.oauth.logout(`${this.origin}/`)
  }
}
