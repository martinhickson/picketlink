import { Routes } from '@angular/router';
import { ClientsPage } from './pages/clients.page';
import { PoliciesPage } from './pages/policies.page';
import { KeysPage } from './pages/keys.page';
import { TokensPage } from './pages/tokens.page';

export const routes: Routes = [
  { path: '', redirectTo: 'clients', pathMatch: 'full' },
  { path: 'clients', component: ClientsPage },
  { path: 'policies', component: PoliciesPage },
  { path: 'keys', component: KeysPage },
  { path: 'tokens', component: TokensPage },
];
