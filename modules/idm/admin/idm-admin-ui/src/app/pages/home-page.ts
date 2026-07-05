import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  standalone: true,
  imports: [RouterLink],
  template: `
    <div class="card">
      <h1>Identity and deployment administration</h1>
      <p class="lead">
        PicketLink IDM Admin helps operators prepare WildFly for SAML federation and OIDC flows.
        Configuration fragments follow <code>saml-setup.md</code> and <code>oidc-setup.md</code>.
      </p>
      <ul class="checklist">
        <li>Timestamped backup of <code>standalone.xml</code> before any edit</li>
        <li>Woodstox StAX event-copy editing for minimal, reviewable diffs</li>
        <li>Restart and WildFly module guidance after changes</li>
        <li>Deployer handoff note for teams maintaining installation runbooks</li>
      </ul>
      <p><a class="btn" routerLink="/assistant">Open configuration assistant</a></p>
      <p><a class="btn btn-secondary" routerLink="/realm-config">Configure realm provider</a></p>
      <p><a class="btn btn-secondary" routerLink="/users">Manage realm users</a></p>
    </div>
  `,
})
export class HomePage {}
