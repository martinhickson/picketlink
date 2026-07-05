import { AsyncPipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  ApplyConfigurationResult,
  ConfigurationProfile,
  StandaloneConfigService,
} from '../services/standalone-config.service';

@Component({
  standalone: true,
  imports: [AsyncPipe, FormsModule],
  template: `
    <div class="card">
      <h1>Configuration assistant</h1>
      <p class="lead">
        Choose the integration profile for this WildFly host. The assistant applies only the Elytron
        and Undertow fragments required for that flow, using a preserving XML editor (Woodstox StAX).
      </p>

      @if (profiles$ | async; as profiles) {
        <div class="grid">
          <label>
            Integration profile
            <select [(ngModel)]="selectedProfileId">
              @for (profile of profiles; track profile.id) {
                <option [value]="profile.id">{{ profile.title }}</option>
              }
            </select>
          </label>

          @if (selectedProfile(profiles); as profile) {
            <p>{{ profile.description }}</p>
            @if (!profile.mutatesStandaloneXml) {
              <div class="note">
                This profile does not change <code>standalone.xml</code>. Review the in-application
                OIDC client filter and WAR configuration instead.
              </div>
            }
          }

          <label>
            WildFly home (JBoss home directory)
            <input type="text" [(ngModel)]="jbossHome" placeholder="/opt/wildfly-36" />
          </label>

          <label>
            <input type="checkbox" [(ngModel)]="removeHttpsListener" />
            Remove default HTTPS listener (local HTTP demo only)
          </label>

          <button (click)="apply(profiles)" [disabled]="applying() || !jbossHome.trim()">
            Apply configuration
          </button>
        </div>
      }

      @if (errorMessage()) {
        <div class="warn">{{ errorMessage() }}</div>
      }

      @if (result()) {
        <div class="ok">
          <h2>Next steps</h2>
          <ul class="checklist">
            @for (message of result()!.messages; track message) {
              <li>{{ message }}</li>
            }
          </ul>
        </div>
        <div class="warn">
          <strong>Restart required:</strong>
          {{ result()!.restartRequired ? 'Yes — restart WildFly before testing.' : 'No server restart needed for this profile.' }}
        </div>
        @if (result()!.requiresWildFlyModule) {
          <div class="note">
            Install the <code>org.picketlink</code> WildFly module on this host (required for SAML
            mechanism factories and federation bindings).
          </div>
        }
        <div class="card">
          <h2>Deployer handoff</h2>
          <p>{{ result()!.deployerHandoffNote }}</p>
          <p>Backup file: <code>{{ result()!.backupFile }}</code></p>
        </div>
      }
    </div>
  `,
})
export class AssistantPage {
  private readonly configService = inject(StandaloneConfigService);

  protected readonly profiles$ = this.configService.listProfiles();
  protected selectedProfileId = 'SAML';
  protected jbossHome = '';
  protected removeHttpsListener = false;
  protected applying = signal(false);
  protected errorMessage = signal('');
  protected result = signal<ApplyConfigurationResult | null>(null);

  protected selectedProfile(profiles: ConfigurationProfile[]): ConfigurationProfile | undefined {
    return profiles.find((profile) => profile.id === this.selectedProfileId);
  }

  protected apply(profiles: ConfigurationProfile[]): void {
    this.applying.set(true);
    this.errorMessage.set('');
    this.result.set(null);
    this.configService
      .applyProfile(this.selectedProfileId, this.jbossHome.trim(), this.removeHttpsListener)
      .subscribe({
        next: (response) => {
          this.result.set(response);
          this.applying.set(false);
        },
        error: (err) => {
          this.errorMessage.set(err?.error?.error ?? err?.message ?? 'Configuration failed');
          this.applying.set(false);
        },
      });
  }
}
