import { createCustomElement } from '@angular/elements';
import { createApplication } from '@angular/platform-browser';
import { provideRouter, withHashLocation } from '@angular/router';
import { routes } from './app/app.routes';
import { AdminConfig } from './app/services/admin-config';
import { AdminApiService } from './app/services/admin-api.service';
import { PicketlinkAdminElement } from './app/picketlink-admin-element';

/**
 * Registers <picketlink-admin> as a standards-compliant web component. Corporate Angular,
 * React or plain-JS sites embed it with:
 *
 *   <script src="main.js"></script>
 *   <picketlink-admin api-base="/api/auth/admin" token="..."></picketlink-admin>
 *
 * Internal routing uses HashLocationStrategy (#/clients, #/policies, ...) so the element's
 * routes never collide with the host application's router and need no server rewrites.
 */
(async () => {
  const app = await createApplication({
    providers: [AdminConfig, AdminApiService, provideRouter(routes, withHashLocation())],
  });
  const element = createCustomElement(PicketlinkAdminElement, { injector: app.injector });
  customElements.define('picketlink-admin', element);
})();
