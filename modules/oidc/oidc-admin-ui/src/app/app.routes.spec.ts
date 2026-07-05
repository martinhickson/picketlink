import { routes } from './app.routes';
import { AdminComponent } from './admin.component';
import { HomeComponent } from './home.component';
import { SecuredComponent } from './secured.component';

describe('app routes', () => {
  it('maps core OIDC admin pages', () => {
    expect(routes).toEqual([
      { path: '', component: HomeComponent },
      { path: 'admin', component: AdminComponent },
      { path: 'secured', component: SecuredComponent },
      { path: '**', redirectTo: '' },
    ]);
  });
});
