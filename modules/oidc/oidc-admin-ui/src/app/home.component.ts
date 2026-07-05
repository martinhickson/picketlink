import { Component, inject } from '@angular/core';
import { AsyncPipe, JsonPipe } from '@angular/common';
import { ApiService } from './api.service';

@Component({
  standalone: true,
  imports: [AsyncPipe, JsonPipe],
  template: `
    <div class="card">
      <h1>Identity Provider</h1>
      <p>Login for SAML assertions: <code>user1</code> / <code>password1</code></p>
      <p><a class="btn" href="../FormLoginServlet">IDP Form Login</a>
         <a class="btn btn-secondary" href="../LogoutServlet">Logout</a></p>
      <h3>CXF REST: /api/info</h3>
      <pre>{{ info$ | async | json }}</pre>
    </div>
  `
})
export class HomeComponent {
  private api = inject(ApiService);
  info$ = this.api.info();
}
