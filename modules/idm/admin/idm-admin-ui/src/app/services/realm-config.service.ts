import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface IdmRealmConfigState {
  configFile: string;
  provider: 'document' | 'scim' | string;
  scimBaseUrl: string;
  useDefaultBaseUrl: boolean;
  defaultScimBaseUrl: string;
  effectiveScimBaseUrl: string;
  scimContextPath: string;
  bearerToken: string;
  syncToDocument: boolean;
  usersPath: string;
  groupsPath: string;
  rolesPath: string;
}

@Injectable({ providedIn: 'root' })
export class RealmConfigService {
  private http = inject(HttpClient);
  private base = '../api/idm/realm/config';

  loadConfig(): Observable<IdmRealmConfigState> {
    return this.http.get<IdmRealmConfigState>(this.base);
  }

  saveConfig(config: IdmRealmConfigState): Observable<IdmRealmConfigState> {
    const params = new HttpParams()
      .set('provider', config.provider)
      .set('scimBaseUrl', config.scimBaseUrl ?? '')
      .set('useDefaultBaseUrl', String(config.useDefaultBaseUrl))
      .set('scimContextPath', config.scimContextPath ?? '/scim')
      .set('bearerToken', config.bearerToken ?? '')
      .set('syncToDocument', String(config.syncToDocument))
      .set('usersPath', config.usersPath ?? '/Users')
      .set('groupsPath', config.groupsPath ?? '/Groups')
      .set('rolesPath', config.rolesPath ?? '/Roles');
    return this.http.post<IdmRealmConfigState>(this.base, null, { params });
  }
}
