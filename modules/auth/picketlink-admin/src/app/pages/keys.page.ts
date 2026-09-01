import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, signal } from '@angular/core';
import { AdminApiService } from '../services/admin-api.service';

@Component({
  selector: 'plk-keys-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h2>Signing keys</h2>
    <p class="plk-hint">Rotated keys keep validating until removed (overlap window). Private material never leaves the keystore.</p>
    <p>
      <button type="button" (click)="rotate()">Rotate signing key</button>
    </p>
    <table class="plk-table">
      <thead>
        <tr><th>Key ID</th><th>Algorithm</th><th>Keystore alias</th><th>Created</th><th></th></tr>
      </thead>
      <tbody>
        @for (key of keys(); track key.keyId) {
          <tr>
            <td>{{ key.keyId }} @if (key.active) { <em>(active)</em> }</td>
            <td>{{ key.algorithm }}</td>
            <td>{{ key.keystoreAlias }}</td>
            <td>{{ key.createdAt * 1000 | date:'medium' }}</td>
            <td>
              @if (!key.active) {
                <button type="button" (click)="activate(key.keyId)">Activate</button>
              }
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
    `,
  ],
  imports: [DatePipe],
})
export class KeysPage implements OnInit {
  keys = signal<any[]>([]);
  error = signal<string | null>(null);

  constructor(private api: AdminApiService) {}

  ngOnInit(): void {
    this.reload();
  }

  reload(): void {
    this.api.listKeys().then(
      (doc) => this.keys.set(doc.keys ?? []),
      (err) => this.error.set(String(err.message ?? err)),
    );
  }

  rotate(): void {
    this.api.rotateKey().then(
      () => this.reload(),
      (err) => this.error.set(String(err.message ?? err)),
    );
  }

  activate(keyId: string): void {
    this.api.activateKey(keyId).then(
      () => this.reload(),
      (err) => this.error.set(String(err.message ?? err)),
    );
  }
}
