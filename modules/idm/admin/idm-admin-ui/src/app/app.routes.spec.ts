import { routes } from './app.routes';
import { AssistantPage } from './pages/assistant-page';
import { HomePage } from './pages/home-page';
import { RealmConfigPage } from './pages/realm-config-page';
import { UsersPage } from './pages/users-page';

describe('app routes', () => {
  it('maps core admin pages', () => {
    expect(routes).toEqual([
      { path: '', component: HomePage },
      { path: 'assistant', component: AssistantPage },
      { path: 'realm-config', component: RealmConfigPage },
      { path: 'users', component: UsersPage },
      { path: '**', redirectTo: '' },
    ]);
  });
});
