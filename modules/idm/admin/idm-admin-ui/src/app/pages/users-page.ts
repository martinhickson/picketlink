import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RealmUserService, IdmRealmState } from '../services/realm-user.service';

@Component({
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="card">
      <h1>Realm users</h1>
      <p>
        Manage OIDC Authorization Server login users through the pluggable realm backend
        (JSON document store or remote SCIM).
      </p>

      @if (realm(); as state) {
        <div class="grid">
          <p>Provider: <strong>{{ state.provider }}</strong></p>
          @if (state.provider === 'scim' && state.scimBaseUrl) {
            <p>SCIM base URL: <code>{{ state.scimBaseUrl }}</code></p>
          }
          @if (state.provider === 'document') {
            <p>Document version: <strong>{{ state.version }}</strong></p>
          }
        </div>

        @if (state.roles.length > 0) {
          <h2>Roles</h2>
          <p>{{ state.roles.join(', ') }}</p>
        }

        @if (state.groups.length > 0) {
          <h2>Groups</h2>
          <p>{{ state.groups.join(', ') }}</p>
        }
      }

      <form class="grid" (ngSubmit)="createUser()">
        <label>Login name <input name="loginName" [(ngModel)]="loginName" required /></label>
        <label>Password <input name="password" type="password" [(ngModel)]="password" required /></label>
        <label>Roles (comma-separated) <input name="roles" [(ngModel)]="roles" /></label>
        <button class="btn" type="submit" [disabled]="saving()">Add user</button>
      </form>
      @if (message()) {
        <p>{{ message() }}</p>
      }

      <table>
        <thead>
          <tr><th>Login</th><th>Roles</th><th>Enabled</th><th></th></tr>
        </thead>
        <tbody>
          @for (user of realm()?.users ?? []; track user.id) {
            <tr>
              <td>{{ user.loginName }}</td>
              <td>{{ user.roles.join(', ') }}</td>
              <td>{{ user.enabled }}</td>
              <td><button class="btn btn-secondary" type="button" (click)="removeUser(user.id)">Delete</button></td>
            </tr>
          }
        </tbody>
      </table>
    </div>
  `
})
export class UsersPage {
  private api = inject(RealmUserService);
  realm = signal<IdmRealmState | null>(null);
  loginName = '';
  password = '';
  roles = 'role1';
  saving = signal(false);
  message = signal('');
  protected readonly isScimProvider = computed(() => this.realm()?.provider === 'scim');

  constructor() {
    this.refresh();
  }

  refresh(): void {
    this.api.loadRealm().subscribe({
      next: (state) => this.realm.set(state),
      error: (err) => this.message.set('Failed to load realm: ' + (err?.message ?? err))
    });
  }

  createUser(): void {
    const current = this.realm();
    if (!current) {
      return;
    }
    this.saving.set(true);
    this.message.set('');
    this.api.createUser(current.version, this.loginName, this.password, this.roles).subscribe({
      next: (state) => {
        this.realm.set(state);
        this.loginName = '';
        this.password = '';
        this.saving.set(false);
        this.message.set('User created.');
      },
      error: (err) => {
        this.saving.set(false);
        this.message.set('Create failed (refresh if version conflict): ' + (err?.message ?? err));
        this.refresh();
      }
    });
  }

  removeUser(userId: string): void {
    const current = this.realm();
    if (!current) {
      return;
    }
    this.api.deleteUser(current.version, userId).subscribe({
      next: (state) => {
        this.realm.set(state);
        this.message.set('User deleted.');
      },
      error: () => {
        this.message.set('Delete failed — refreshing realm state.');
        this.refresh();
      }
    });
  }
}
