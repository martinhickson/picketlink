import { ChangeDetectionStrategy, Component, OnInit, signal } from '@angular/core';
import { AdminApiService } from '../services/admin-api.service';

@Component({
  selector: 'plk-tokens-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h2>Issued tokens</h2>
    <p class="plk-hint">Token hashes only — raw JWTs are never stored or displayed. Revoking a hash revokes the token everywhere.</p>
    <table class="plk-table">
      <thead>
        <tr><th>Token hash</th><th>Client</th><th>Scopes</th><th>Issued</th><th>Expires</th><th></th></tr>
      </thead>
      <tbody>
        @for (token of tokens(); track token.tokenHash) {
          <tr>
            <td><code>{{ token.tokenHash.substring(0, 12) }}…</code></td>
            <td>{{ token.clientId }}</td>
            <td>{{ token.scopes }}</td>
            <td>{{ token.issuedAt }}</td>
            <td>{{ token.expiresAt }}</td>
            <td>
              <button type="button" class="plk-danger" (click)="revoke(token.tokenHash)">Revoke</button>
            </td>
          </tr>
        }
      </tbody>
    </table>
    @if (error()) {
      <p class="plk-error">{{ error() }}</p>
    }
  `,
  styles: [
    `
      .plk-table { border-collapse: collapse; width: 100%; }
      .plk-table th, .plk-table td { border: 1px solid #d7dae0; padding: .4rem .6rem; text-align: left; }
      .plk-danger { color: #b91c1c; }
    `,
  ],
})
export class TokensPage implements OnInit {
  tokens = signal<any[]>([]);
  error = signal<string | null>(null);

  constructor(private api: AdminApiService) {}

  ngOnInit(): void {
    this.reload();
  }

  reload(): void {
    this.api.listTokens().then(
      (tokens) => this.tokens.set(tokens),
      (err) => this.error.set(String(err.message ?? err)),
    );
  }

  revoke(tokenHash: string): void {
    this.api.revokeToken(tokenHash).then(
      () => this.reload(),
      (err) => this.error.set(String(err.message ?? err)),
    );
  }
}
