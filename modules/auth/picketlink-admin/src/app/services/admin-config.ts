import { Injectable } from '@angular/core';

/** Element configuration shared between <picketlink-admin> inputs and the API services. */
@Injectable()
export class AdminConfig {
  apiBase = '../api/auth/admin';
  tokenEndpoint = '../oauth/token';
  staticToken: string | null = null;
  clientId: string | null = null;
  clientSecret: string | null = null;
}
