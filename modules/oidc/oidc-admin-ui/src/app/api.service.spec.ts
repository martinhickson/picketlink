import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ApiService } from './api.service';

describe('ApiService', () => {
  let service: ApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [ApiService, provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('loads server info', () => {
    service.info().subscribe((info) => {
      expect(info).toEqual({ name: 'oidc-as' });
    });
    const req = httpMock.expectOne('../api/info');
    expect(req.request.method).toBe('GET');
    req.flush({ name: 'oidc-as' });
  });

  it('loads signing keys', () => {
    service.signingKeys().subscribe((keys) => {
      expect(keys).toEqual({ keys: [] });
    });
    httpMock.expectOne('../api/keys').flush({ keys: [] });
  });

  it('rotates the signing key', () => {
    service.rotateSigningKey(30).subscribe((result) => {
      expect(result.activeAlias).toBe('oidc-signing-2');
      expect(result.generation).toBe(2);
    });

    const req = httpMock.expectOne('../api/keys/rotate?validityDays=30');
    expect(req.request.method).toBe('POST');
    req.flush({ activeAlias: 'oidc-signing-2', generation: 2 });
  });

  it('loads realm users', () => {
    service.realmUsers().subscribe((state) => {
      expect(state.version).toBe(1);
      expect(state.users.length).toBe(1);
    });
    httpMock.expectOne('../api/idm/realm/users').flush({
      documentId: 'picketlink-idm-realm',
      version: 1,
      users: [{ id: 'u1' }],
    });
  });

  it('creates a realm user', () => {
    service.createRealmUser(1, 'alice', 'secret', 'role1').subscribe();

    const req = httpMock.expectOne(
      (request) =>
        request.url === '../api/idm/realm/users' &&
        request.method === 'POST' &&
        request.params.get('loginName') === 'alice',
    );
    req.flush({ version: 2, users: [] });
  });

  it('loads federation metadata', () => {
    service.metadataJson().subscribe((metadata) => {
      expect(metadata).toEqual({ entityId: 'urn:test' });
    });
    httpMock.expectOne('../api/admin/federation/metadata').flush({ entityId: 'urn:test' });
  });
});
