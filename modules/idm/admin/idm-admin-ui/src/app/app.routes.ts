import { Routes } from '@angular/router';
import { AssistantPage } from './pages/assistant-page';
import { HomePage } from './pages/home-page';
import { RealmConfigPage } from './pages/realm-config-page';
import { UsersPage } from './pages/users-page';

export const routes: Routes = [
  { path: '', component: HomePage },
  { path: 'assistant', component: AssistantPage },
  { path: 'realm-config', component: RealmConfigPage },
  { path: 'users', component: UsersPage },
  { path: '**', redirectTo: '' },
];
