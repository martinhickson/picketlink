import { Component, inject, signal } from '@angular/core';
import { AsyncPipe, JsonPipe } from '@angular/common';
import { ApiService } from './api.service';

@Component({
  standalone: true,
  imports: [AsyncPipe, JsonPipe],
  template: `
    <div class="card">
      <h1>OIDC Authorization Server Admin</h1>
      <div class="grid">
        <a class="btn" href="../.well-known/openid-configuration" target="_blank">OIDC Discovery</a>
        <a class="btn" href="../oidc/jwks" target="_blank">JWKS</a>
        <a class="btn" href="../api/info" target="_blank">CXF Demo Info (JSON)</a>
        <a class="btn btn-secondary" href="../FormLoginServlet">Login</a>
      </div>

      <h3>Signing keys</h3>
      <p>Rotate the OIDC signing certificate without restarting WildFly. POST requires login as a realm user.</p>
      <button class="btn" (click)="rotate()" [disabled]="rotating()">Rotate signing key</button>
      @if (rotationMessage()) {
        <p>{{ rotationMessage() }}</p>
      }
      <pre>{{ keys$ | async | json }}</pre>

      <h3>Realm users</h3>
      <p>Users are mastered in the pluggable IDM JSON document store (not Elytron properties-realm).</p>
      <pre>{{ realmUsers$ | async | json }}</pre>

      <h3>Server info</h3>
      <pre>{{ info$ | async | json }}</pre>
    </div>
  `
})
export class AdminComponent {
  private api = inject(ApiService);
  info$ = this.api.info();
  keys$ = this.api.signingKeys();
  realmUsers$ = this.api.realmUsers();
  rotating = signal(false);
  rotationMessage = signal('');

  rotate(): void {
    this.rotating.set(true);
    this.rotationMessage.set('');
    this.api.rotateSigningKey().subscribe({
      next: (result) => {
        this.rotationMessage.set('Rotated active alias to ' + result.activeAlias);
        this.keys$ = this.api.signingKeys();
        this.rotating.set(false);
      },
      error: (err) => {
        this.rotationMessage.set('Rotation failed (login required for POST): ' + (err?.message ?? err));
        this.rotating.set(false);
      }
    });
  }
}
