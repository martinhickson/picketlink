import { Component } from '@angular/core';

@Component({
  standalone: true,
  template: `
    <div class="card">
      <h1>Secured IDP Area</h1>
      <p>Requires FORM authentication (user1/password1).</p>
      <div class="grid">
        <a class="btn" href="../FormLoginServlet">Login</a>
        <a class="btn btn-secondary" href="../LogoutServlet">Logout</a>
      </div>
    </div>
  `
})
export class SecuredComponent {}
