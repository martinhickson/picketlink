import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ClientRegistrationService } from './client-registration.service';

describe('ClientRegistrationService', () => {
  let service: ClientRegistrationService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [ClientRegistrationService, provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ClientRegistrationService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('lists registered clients', () => {
    service.listClients().subscribe((clients) => {
      expect(clients.length).toBe(1);
      expect(clients[0].clientId).toBe('demo-client');
    });

    const req = httpMock.expectOne('/api/auth/clients');
    expect(req.request.method).toBe('GET');
    req.flush([
      {
        clientId: 'demo-client',
        clientSecret: 'secret',
        scopes: ['api.read'],
        tokenEndpointAuthMethod: 'client_secret_basic',
      },
    ]);
  });

  it('registers a client', () => {
    service
      .registerClient({
        clientId: 'new-client',
        scopes: ['api.read'],
        tokenEndpointAuthMethod: 'client_secret_basic',
      })
      .subscribe((created) => {
        expect(created.clientId).toBe('new-client');
        expect(created.clientSecret).toBe('generated-secret');
      });

    const req = httpMock.expectOne('/api/auth/clients');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({
      clientId: 'new-client',
      scopes: ['api.read'],
      tokenEndpointAuthMethod: 'client_secret_basic',
    });
    req.flush({
      clientId: 'new-client',
      clientSecret: 'generated-secret',
      scopes: ['api.read'],
      tokenEndpointAuthMethod: 'client_secret_basic',
    });
  });

  it('deletes a client by id', () => {
    service.deleteClient('demo-client').subscribe();

    const req = httpMock.expectOne('/api/auth/clients/demo-client');
    expect(req.request.method).toBe('DELETE');
    req.flush(null);
  });
});
