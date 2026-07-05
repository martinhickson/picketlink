import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(private http: HttpClient) {}

  info(): Observable<unknown> {
    return this.http.get('../api/info');
  }

  signingKeys(): Observable<unknown> {
    return this.http.get('../api/keys');
  }

  rotateSigningKey(validityDays = 365): Observable<{ activeAlias: string; generation: number }> {
    return this.http.post<{ activeAlias: string; generation: number }>(
      '../api/keys/rotate?validityDays=' + validityDays,
      null);
  }

  realmUsers(): Observable<{ documentId: string; version: number; users: unknown[] }> {
    return this.http.get<{ documentId: string; version: number; users: unknown[] }>(
      '../api/idm/realm/users');
  }

  createRealmUser(version: number, loginName: string, password: string, roles: string): Observable<unknown> {
    return this.http.post('../api/idm/realm/users', null, {
      params: {
        version: String(version),
        loginName,
        password,
        roles
      }
    });
  }

  metadataJson(): Observable<unknown> {
    return this.http.get('../api/admin/federation/metadata');
  }
}
