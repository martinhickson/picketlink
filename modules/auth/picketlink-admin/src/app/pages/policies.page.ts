import { ChangeDetectionStrategy, Component, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AdminApiService } from '../services/admin-api.service';

@Component({
  selector: 'plk-policies-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h2>Issuance policy</h2>
    <p class="plk-hint">Applies to every token issued through the JWT issuance manager.</p>
    <form class="plk-form" (ngSubmit)="save()">
      <label>Allowed signing algorithms (comma separated)
        <input name="allowed" [(ngModel)]="allowedAlgorithms" />
      </label>
      <label>Default algorithm <input name="default" [(ngModel)]="defaultAlgorithm" /></label>
      <label>Default lifetime (seconds)
        <input name="defaultLifetime" type="number" [(ngModel)]="defaultLifetimeSeconds" />
      </label>
      <label>Maximum lifetime (seconds)
        <input name="maxLifetime" type="number" [(ngModel)]="maxLifetimeSeconds" />
      </label>
      <button type="submit">Save</button>
      @if (status()) {
        <span class="plk-status">{{ status() }}</span>
      }
    </form>
    @if (error()) {
      <p class="plk-error">{{ error() }}</p>
    }
  `,
  styles: [
    `
      .plk-form { display: grid; gap: .6rem; max-width: 30rem; }
      .plk-form label { display: grid; gap: .2rem; font-size: .9rem; }
    `,
  ],
  imports: [FormsModule],
})
export class PoliciesPage implements OnInit {
  allowedAlgorithms = 'RS256, ES256';
  defaultAlgorithm = 'RS256';
  defaultLifetimeSeconds = 300;
  maxLifetimeSeconds = 600;
  status = signal<string | null>(null);
  error = signal<string | null>(null);

  constructor(private api: AdminApiService) {}

  ngOnInit(): void {
    this.api.getPolicy().then(
      (policy) => {
        this.allowedAlgorithms = (policy.allowedAlgorithms ?? []).join(', ');
        this.defaultAlgorithm = policy.defaultAlgorithm ?? 'RS256';
        this.defaultLifetimeSeconds = policy.defaultLifetimeSeconds ?? 300;
        this.maxLifetimeSeconds = policy.maxLifetimeSeconds ?? 600;
      },
      (err) => this.error.set(String(err.message ?? err)),
    );
  }

  save(): void {
    this.status.set(null);
    this.error.set(null);
    this.api
      .savePolicy({
        allowedAlgorithms: this.allowedAlgorithms.split(',').map((a) => a.trim()).filter(Boolean),
        defaultAlgorithm: this.defaultAlgorithm,
        defaultLifetimeSeconds: Number(this.defaultLifetimeSeconds),
        maxLifetimeSeconds: Number(this.maxLifetimeSeconds),
      })
      .then(
        () => this.status.set('Saved'),
        (err) => this.error.set(String(err.message ?? err)),
      );
  }
}
