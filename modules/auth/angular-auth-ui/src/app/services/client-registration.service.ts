import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import {
  ClientRegistrationRequest,
  ClientRegistrationView,
} from '../models/client-registration';

@Injectable({ providedIn: 'root' })
export class ClientRegistrationService {
  private readonly http = inject(HttpClient);
  private readonly apiBase = '/api/auth/clients';

  listClients() {
    return this.http.get<ClientRegistrationView[]>(this.apiBase);
  }

  registerClient(request: ClientRegistrationRequest) {
    return this.http.post<ClientRegistrationView>(this.apiBase, request);
  }

  deleteClient(clientId: string) {
    return this.http.delete<void>(`${this.apiBase}/${encodeURIComponent(clientId)}`);
  }
}
