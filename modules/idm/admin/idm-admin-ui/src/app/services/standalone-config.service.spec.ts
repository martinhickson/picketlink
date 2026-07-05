import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { StandaloneConfigService } from './standalone-config.service';

describe('StandaloneConfigService', () => {
  let service: StandaloneConfigService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [StandaloneConfigService, provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(StandaloneConfigService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('lists configuration profiles', () => {
    service.listProfiles().subscribe((profiles) => {
      expect(profiles.length).toBe(1);
      expect(profiles[0].id).toBe('SAML');
    });

    const req = httpMock.expectOne('../api/idm/standalone/profiles');
    expect(req.request.method).toBe('GET');
    req.flush([
      {
        id: 'SAML',
        title: 'SAML SP',
        description: 'SAML service provider profile',
        mutatesStandaloneXml: true,
        requiresWildFlyModule: true,
      },
    ]);
  });

  it('applies a profile with query parameters', () => {
    service.applyProfile('OIDC-AS', '/opt/wildfly', true).subscribe((result) => {
      expect(result.profileId).toBe('OIDC-AS');
      expect(result.changed).toBe(true);
    });

    const req = httpMock.expectOne(
      (request) =>
        request.url === '../api/idm/standalone/apply' &&
        request.method === 'POST' &&
        request.params.get('profile') === 'OIDC-AS' &&
        request.params.get('jbossHome') === '/opt/wildfly' &&
        request.params.get('removeHttpsListener') === 'true',
    );
    req.flush({
      profileId: 'OIDC-AS',
      standaloneXml: '<server/>',
      backupPath: '/tmp',
      backupFile: 'standalone.xml.bak',
      changed: true,
      restartRequired: true,
      httpsListenersRemoved: 1,
      requiresWildFlyModule: true,
      deployerHandoffNote: 'Restart WildFly',
      messages: ['Applied OIDC profile'],
    });
  });
});
