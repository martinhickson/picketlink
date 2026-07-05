import { routes } from './app.routes';
import { ClientRegistryPage } from './pages/client-registry-page';

describe('app routes', () => {
  it('maps the default path to the client registry page', () => {
    expect(routes[0]).toEqual({ path: '', component: ClientRegistryPage });
  });

  it('redirects unknown paths to the registry page', () => {
    expect(routes.at(-1)).toEqual({ path: '**', redirectTo: '' });
  });
});
