import { Routes } from '@angular/router';
import { ClientRegistryPage } from './pages/client-registry-page';

export const routes: Routes = [
  { path: '', component: ClientRegistryPage },
  { path: '**', redirectTo: '' },
];
