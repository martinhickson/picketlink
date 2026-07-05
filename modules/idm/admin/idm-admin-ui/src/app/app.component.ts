import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <nav>
      <strong>PicketLink IDM Admin</strong>
      <a routerLink="/" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: true }">Overview</a>
      <a routerLink="/assistant" routerLinkActive="active">Configuration assistant</a>
      <a routerLink="/realm-config" routerLinkActive="active">Realm provider</a>
      <a routerLink="/users" routerLinkActive="active">Realm users</a>
    </nav>
    <main><router-outlet /></main>
  `,
})
export class AppComponent {}
