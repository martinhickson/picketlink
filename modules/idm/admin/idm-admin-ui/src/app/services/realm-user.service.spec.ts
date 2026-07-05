import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { RealmUserService } from './realm-user.service';

describe('RealmUserService', () => {
  let service: RealmUserService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [RealmUserService, provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(RealmUserService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('loads realm state', () => {
    service.loadRealm().subscribe((state) => {
      expect(state.documentId).toBe('picketlink-idm-realm');
      expect(state.version).toBe(2);
      expect(state.users.length).toBe(1);
    });

    const req = httpMock.expectOne('../api/idm/realm/users');
    expect(req.request.method).toBe('GET');
    req.flush({
      documentId: 'picketlink-idm-realm',
      version: 2,
      provider: 'document',
      roles: ['role1'],
      groups: [],
      users: [{ id: 'u1', loginName: 'alice', enabled: true, roles: ['role1'] }],
    });
  });

  it('creates a user with optimistic-lock version', () => {
    service.createUser(2, 'bob', 'secret', 'role1,role2').subscribe((state) => {
      expect(state.version).toBe(3);
    });

    const req = httpMock.expectOne(
      (request) =>
        request.url === '../api/idm/realm/users' &&
        request.method === 'POST' &&
        request.params.get('version') === '2' &&
        request.params.get('loginName') === 'bob' &&
        request.params.get('password') === 'secret' &&
        request.params.get('roles') === 'role1,role2',
    );
    req.flush({ documentId: 'picketlink-idm-realm', version: 3, users: [] });
  });

  it('deletes a user by id', () => {
    service.deleteUser(4, 'u1').subscribe((state) => {
      expect(state.version).toBe(5);
    });

    const req = httpMock.expectOne(
      (request) =>
        request.url === '../api/idm/realm/users' &&
        request.method === 'DELETE' &&
        request.params.get('version') === '4' &&
        request.params.get('userId') === 'u1',
    );
    req.flush({ documentId: 'picketlink-idm-realm', version: 5, users: [] });
  });
});
