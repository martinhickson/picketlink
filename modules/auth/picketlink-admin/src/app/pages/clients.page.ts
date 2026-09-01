import { ChangeDetectionStrategy, Component, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AdminApiService } from '../services/admin-api.service';

interface ClientRow {
  clientId: string;
  clientSecret: string;
  scopes: string[];
  tokenEndpointAuthMethod: string;
  allowedAudiences: string[];
  hasJwks: boolean;
  maxTokenLifetimeSeconds: number;
}

@Component({
  selector: 'plk-clients-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h2>Clients</h2>
    <p class="plk-hint">REST clients allowed to obtain tokens. Secrets are shown once on creation or rotation.</p>
    <table class="plk-table">
      <thead>
        <tr><th>Client</th><th>Auth method</th><th>Scopes</th><th>Audiences</th><th>Max lifetime</th><th></th></tr>
      </thead>
      <tbody>
        @for (client of clients(); track client.clientId) {
          <tr>
            <td>{{ client.clientId }}</td>
            <td>{{ client.tokenEndpointAuthMethod }}</td>
            <td>{{ client.scopes.join(' ') }}</td>
            <td>{{ client.allowedAudiences.join(' ') }}</td>
            <td>{{ client.maxTokenLifetimeSeconds ? client.maxTokenLifetimeSeconds + 's' : 'default' }}</td>
            <td class="plk-actions">
              <button type="button" (click)="rotateSecret(client.clientId)">Rotate secret</button>
              <button type="button" class="plk-danger" (click)="remove(client.clientId)">Delete</button>
            </td>
          </tr>
        }
      </tbody>
    </table>

    <h3>Create client</h3>
    <form class="plk-form" (ngSubmit)="create()">
      <label>Client ID <input name="clientId" [(ngModel)]="draft.clientId" required /></label>
      <label>Auth method
        <select name="authMethod" [(ngModel)]="draft.tokenEndpointAuthMethod">
          <option value="client_secret_basic">client_secret_basic</option>
          <option value="client_secret_post">client_secret_post</option>
          <option value="private_key_jwt">private_key_jwt (automated)</option>
        </select>
      </label>
      <label>Scopes (space separated) <input name="scopes" [(ngModel)]="draft.scopes" /></label>
      <label>Allowed audiences (space separated) <input name="audiences" [(ngModel)]="draft.allowedAudiences" /></label>
      <label>JWKS (JSON, for private_key_jwt) <textarea name="jwks" rows="4" [(ngModel)]="draft.jwks"></textarea></label>
      <label>Max lifetime (seconds, 0 = default) <input name="maxLifetime" type="number" [(ngModel)]="draft.maxTokenLifetimeSeconds" /></label>
      <button type="submit">Create</button>
      @if (generatedSecret(); as secret) {
        <code class="plk-secret">secret: {{ secret }}</code>
      }
    </form>
    @if (error()) {
      <p class="plk-error">{{ error() }}</p>
    }
  `,
  styles: [
    `
      .plk-table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }
      .plk-table th, .plk-table td { border: 1px solid #d7dae0; padding: .4rem .6rem; text-align: left; }
      .plk-form { display: grid; gap: .6rem; max-width: 34rem; }
      .plk-form label { display: grid; gap: .2rem; font-size: .9rem; }
      .plk-secret { background: #f0fdf4; padding: .4rem; }
      .plk-danger { color: #b91c1c; }
    `,
  ],
  imports: [FormsModule],
})
export class ClientsPage implements OnInit {
  clients = signal<ClientRow[]>([]);
  error = signal<string | null>(null);
  generatedSecret = signal<string | null>(null);

  draft = {
    clientId: '',
    tokenEndpointAuthMethod: 'client_secret_basic',
    scopes: 'read',
    allowedAudiences: '',
    jwks: '',
    maxTokenLifetimeSeconds: 0,
  };

  constructor(private api: AdminApiService) {}

  ngOnInit(): void {
    this.reload();
  }

  reload(): void {
    this.api.listClients().then(
      (clients) => this.clients.set(clients),
      (err) => this.error.set(String(err.message ?? err)),
    );
  }

  create(): void {
    this.generatedSecret.set(null);
    this.error.set(null);
    this.api
      .createClient({
        clientId: this.draft.clientId,
        tokenEndpointAuthMethod: this.draft.tokenEndpointAuthMethod,
        scopes: this.draft.scopes.split(/\s+/).filter(Boolean),
        allowedAudiences: this.draft.allowedAudiences.split(/\s+/).filter(Boolean),
        jwks: this.draft.jwks || undefined,
        maxTokenLifetimeSeconds: Number(this.draft.maxTokenLifetimeSeconds) || 0,
      })
      .then(
        (created) => {
          this.generatedSecret.set(created.clientSecret !== '********' ? created.clientSecret : null);
          this.reload();
        },
        (err) => this.error.set(String(err.message ?? err)),
      );
  }

  rotateSecret(clientId: string): void {
    this.api.rotateSecret(clientId).then(
      (result) => this.generatedSecret.set(result.clientSecret),
      (err) => this.error.set(String(err.message ?? err)),
    );
  }

  remove(clientId: string): void {
    this.api.deleteClient(clientId).then(
      () => this.reload(),
      (err) => this.error.set(String(err.message ?? err)),
    );
  }
}
