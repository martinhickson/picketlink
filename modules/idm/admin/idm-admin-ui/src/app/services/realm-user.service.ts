import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface IdmUser {
  id: string;
  loginName: string;
  enabled: boolean;
  roles: string[];
}

export interface IdmRealmState {
  documentId: string;
  version: number;
  provider: 'document' | 'scim' | string;
  scimBaseUrl?: string;
  users: IdmUser[];
  roles: string[];
  groups: string[];
}

@Injectable({ providedIn: 'root' })
export class RealmUserService {
  private http = inject(HttpClient);
  private base = '../api/idm/realm/users';

  loadRealm(): Observable<IdmRealmState> {
    return this.http.get<IdmRealmState>(this.base);
  }

  createUser(version: number, loginName: string, password: string, roles: string): Observable<IdmRealmState> {
    const params = new HttpParams()
      .set('version', String(version))
      .set('loginName', loginName)
      .set('password', password)
      .set('roles', roles);
    return this.http.post<IdmRealmState>(this.base, null, { params });
  }

  deleteUser(version: number, userId: string): Observable<IdmRealmState> {
    const params = new HttpParams().set('version', String(version)).set('userId', userId);
    return this.http.delete<IdmRealmState>(this.base, { params });
  }
}
