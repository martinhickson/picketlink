import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { RealmConfigService } from './realm-config.service';

const configState = {
  configFile: '/opt/wildfly/standalone/configuration/security/picketlink-realm-config.json',
  provider: 'document',
  scimBaseUrl: '',
  useDefaultBaseUrl: true,
  defaultScimBaseUrl: 'http://127.0.0.1:8080/scim',
  effectiveScimBaseUrl: '',
  scimContextPath: '/scim',
  bearerToken: '',
  syncToDocument: true,
  usersPath: '/Users',
  groupsPath: '/Groups',
  rolesPath: '/Roles',
};

describe('RealmConfigService', () => {
  let service: RealmConfigService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), RealmConfigService],
    });
    service = TestBed.inject(RealmConfigService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('loads realm provider config', () => {
    service.loadConfig().subscribe((state) => {
      expect(state.provider).toBe('document');
      expect(state.defaultScimBaseUrl).toContain('/scim');
    });
    httpMock.expectOne('../api/idm/realm/config').flush(configState);
  });

  it('saves scim provider config', () => {
    service.saveConfig({ ...configState, provider: 'scim', scimBaseUrl: 'http://127.0.0.1:9999/scim', useDefaultBaseUrl: false })
      .subscribe((state) => expect(state.provider).toBe('scim'));

    const req = httpMock.expectOne((request) => request.method === 'POST' && request.url.endsWith('/api/idm/realm/config'));
    expect(req.request.params.get('provider')).toBe('scim');
    expect(req.request.params.get('scimBaseUrl')).toBe('http://127.0.0.1:9999/scim');
    req.flush({ ...configState, provider: 'scim', effectiveScimBaseUrl: 'http://127.0.0.1:9999/scim' });
  });
});
