import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { IdmRealmConfigState, RealmConfigService } from '../services/realm-config.service';

@Component({
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="card">
      <h1>Realm provider</h1>
      <p>
        Choose whether the IDM admin UI reads users from the local JSON/JDBC document store or from a
        remote SCIM server (standard <code>/Users</code>, <code>/Groups</code>, plus PicketLink
        <code>/Roles</code> extension).
      </p>

      @if (config(); as state) {
        <form class="grid" (ngSubmit)="save()">
          <label>
            Provider
            <select name="provider" [(ngModel)]="state.provider" required>
              <option value="document">document (local JSON/JDBC)</option>
              <option value="scim">scim (remote REST)</option>
            </select>
          </label>

          @if (state.provider === 'scim') {
            <label>
              <input type="checkbox" name="useDefaultBaseUrl" [(ngModel)]="state.useDefaultBaseUrl" />
              Use default WildFly SCIM base URL
            </label>

            @if (state.useDefaultBaseUrl) {
              <p>
                Default base URL:
                <code>{{ state.defaultScimBaseUrl }}</code>
              </p>
              <label>
                SCIM context path
                <input name="scimContextPath" [(ngModel)]="state.scimContextPath" placeholder="/scim" />
              </label>
            } @else {
              <label>
                SCIM base URL
                <input
                  name="scimBaseUrl"
                  [(ngModel)]="state.scimBaseUrl"
                  placeholder="https://idp.example.com/scim"
                  required
                />
              </label>
            }

            <p>Effective SCIM URL: <code>{{ state.effectiveScimBaseUrl || state.defaultScimBaseUrl }}</code></p>

            <label>
              Bearer token (optional)
              <input name="bearerToken" [(ngModel)]="state.bearerToken" type="password" autocomplete="off" />
            </label>

            <label>
              <input type="checkbox" name="syncToDocument" [(ngModel)]="state.syncToDocument" />
              Sync SCIM users to local document store (for Elytron FORM login)
            </label>

            <details>
              <summary>Advanced SCIM paths</summary>
              <label>Users path <input name="usersPath" [(ngModel)]="state.usersPath" /></label>
              <label>Groups path <input name="groupsPath" [(ngModel)]="state.groupsPath" /></label>
              <label>Roles path <input name="rolesPath" [(ngModel)]="state.rolesPath" /></label>
            </details>
          }

          <p class="note">Config file: <code>{{ state.configFile }}</code></p>

          <button class="btn" type="submit" [disabled]="saving()">Save provider settings</button>
        </form>
      }

      @if (message()) {
        <p>{{ message() }}</p>
      }
    </div>
  `,
})
export class RealmConfigPage {
  private api = inject(RealmConfigService);
  config = signal<IdmRealmConfigState | null>(null);
  saving = signal(false);
  message = signal('');

  constructor() {
    this.refresh();
  }

  refresh(): void {
    this.api.loadConfig().subscribe({
      next: (state) => this.config.set({ ...state }),
      error: (err) => this.message.set('Failed to load config: ' + (err?.message ?? err)),
    });
  }

  save(): void {
    const current = this.config();
    if (!current) {
      return;
    }
    this.saving.set(true);
    this.message.set('');
    this.api.saveConfig(current).subscribe({
      next: (state) => {
        this.config.set({ ...state });
        this.saving.set(false);
        this.message.set('Provider settings saved. Realm users page will use the new backend.');
      },
      error: (err) => {
        this.saving.set(false);
        this.message.set('Save failed: ' + (err?.message ?? err));
      },
    });
  }
}
