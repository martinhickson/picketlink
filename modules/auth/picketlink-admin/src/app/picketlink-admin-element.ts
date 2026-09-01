import { ChangeDetectionStrategy, Component, Input, OnInit } from '@angular/core';
import { Router, RouterOutlet } from '@angular/router';
import { AdminConfig } from './services/admin-config';

/**
 * Root of the <picketlink-admin> web component. Inputs are plain element attributes, so the
 * host site can configure everything without any Angular knowledge:
 *
 * - api-base: base URL of the admin API (default "../api/auth/admin" — same-origin deploys)
 * - token: bearer token granting the auth-admin scope (host owns login)
 * - client-id / client-secret: alternatively, the element fetches its own token via the
 *   OAuth2 client_credentials token endpoint (token-endpoint attribute, default "../oauth/token")
 *
 * Routing uses withHashLocation() (#/clients, #/policies, ...) so the element's routes never
 * collide with the host application's router and need no server-side rewrites.
 */
@Component({
  selector: 'plk-picketlink-admin',
  imports: [RouterOutlet],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <nav class="plk-nav">
      <a href="#/clients">Clients</a>
      <a href="#/policies">Policies</a>
      <a href="#/keys">Signing keys</a>
      <a href="#/tokens">Tokens</a>
      <span class="plk-brand">PicketLink</span>
    </nav>
    <main class="plk-main">
      <router-outlet />
    </main>
  `,
  styles: [
    `
      :host { display: block; font-family: system-ui, sans-serif; color: #1a1a2e; }
      .plk-nav { display: flex; gap: 1rem; align-items: center; padding: .6rem 1rem;
                 background: #16213e; }
      .plk-nav a { color: #e2e8f0; text-decoration: none; font-size: .95rem; }
      .plk-nav a:hover { text-decoration: underline; }
      .plk-brand { margin-left: auto; color: #8be9fd; font-weight: 600; }
      .plk-main { padding: 1rem; }
    `,
  ],
})
export class PicketlinkAdminElement implements OnInit {
  @Input({ alias: 'api-base' }) apiBase = '../api/auth/admin';
  @Input({ alias: 'token' }) token: string | null = null;
  @Input({ alias: 'token-endpoint' }) tokenEndpoint = '../oauth/token';
  @Input({ alias: 'client-id' }) clientId: string | null = null;
  @Input({ alias: 'client-secret' }) clientSecret: string | null = null;

  constructor(private config: AdminConfig, private router: Router) {}

  ngOnInit(): void {
    this.config.apiBase = this.apiBase;
    this.config.staticToken = this.token;
    this.config.tokenEndpoint = this.tokenEndpoint;
    this.config.clientId = this.clientId;
    this.config.clientSecret = this.clientSecret;
    // element-only apps have no bootstrap component, so ApplicationRef stability may never
    // signal the router's initial navigation — trigger it explicitly (idempotent)
    this.router.initialNavigation();
  }
}
