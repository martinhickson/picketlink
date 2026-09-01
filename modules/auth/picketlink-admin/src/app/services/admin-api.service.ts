import { Injectable } from '@angular/core';
import { AdminConfig } from './admin-config';

/**
 * Typed-ish REST client for the PicketLink admin API. Bearer handling: uses the token given
 * by the host site, or performs a client_credentials request itself when client-id/client-secret
 * attributes were provided. Built on fetch() — no Angular HTTP interdependences, so this
 * service layer can also be reused standalone in non-Angular sites.
 */
@Injectable()
export class AdminApiService {

  private cachedToken: string | null = null;
  private tokenExpires = 0;

  constructor(private config: AdminConfig) {}

  private async token(): Promise<string> {
    if (this.config.staticToken) {
      return this.config.staticToken;
    }
    if (this.config.clientId && this.config.clientSecret) {
      if (this.cachedToken && Date.now() < this.tokenExpires - 30_000) {
        return this.cachedToken;
      }
      const body = new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'auth-admin',
      });
      const response = await fetch(this.config.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: 'Basic ' + btoa(this.config.clientId + ':' + this.config.clientSecret),
        },
        body: body.toString(),
      });
      if (!response.ok) {
        throw new Error('Token request failed: ' + response.status);
      }
      const json = (await response.json()) as { access_token: string; expires_in: number };
      this.cachedToken = json.access_token;
      this.tokenExpires = Date.now() + json.expires_in * 1000;
      return this.cachedToken!;
    }
    throw new Error('Provide either a token or client-id/client-secret attribute');
  }

  async request(method: string, path: string, body?: unknown): Promise<any> {
    const headers: Record<string, string> = {
      Authorization: 'Bearer ' + (await this.token()),
    };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    const response = await fetch(this.config.apiBase + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 204 || response.headers.get('content-length') === '0') {
      return null;
    }
    const text = await response.text();
    const json = text ? JSON.parse(text) : null;
    if (!response.ok) {
      throw new Error((json && json.error) || ('Request failed: ' + response.status));
    }
    return json;
  }

  // clients
  listClients(): Promise<any[]> {
    return this.request('GET', '/clients');
  }

  createClient(client: any): Promise<any> {
    return this.request('POST', '/clients', client);
  }

  updateClient(clientId: string, client: any): Promise<any> {
    return this.request('PUT', '/clients/' + encodeURIComponent(clientId), client);
  }

  rotateSecret(clientId: string): Promise<any> {
    return this.request('POST', '/clients/' + encodeURIComponent(clientId) + '/rotate-secret');
  }

  deleteClient(clientId: string): Promise<any> {
    return this.request('DELETE', '/clients/' + encodeURIComponent(clientId));
  }

  // policies
  getPolicy(): Promise<any> {
    return this.request('GET', '/policies');
  }

  savePolicy(policy: any): Promise<any> {
    return this.request('PUT', '/policies', policy);
  }

  // keys
  listKeys(): Promise<any> {
    return this.request('GET', '/keys');
  }

  rotateKey(): Promise<any> {
    return this.request('POST', '/keys/rotate');
  }

  activateKey(keyId: string): Promise<any> {
    return this.request('PUT', '/keys/' + encodeURIComponent(keyId) + '/activate');
  }

  // tokens
  listTokens(limit = 100): Promise<any[]> {
    return this.request('GET', '/tokens?limit=' + limit);
  }

  revokeToken(tokenHash: string): Promise<any> {
    return this.request('DELETE', '/tokens/' + encodeURIComponent(tokenHash));
  }
}
