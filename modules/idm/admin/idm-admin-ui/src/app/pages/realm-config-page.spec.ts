import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { RealmConfigPage } from './realm-config-page';

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

describe('RealmConfigPage', () => {
  let fixture: ComponentFixture<RealmConfigPage>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [RealmConfigPage],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(RealmConfigPage);
    fixture.detectChanges();
    httpMock.expectOne('../api/idm/realm/config').flush(configState);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('renders document provider by default', () => {
    expect(fixture.nativeElement.textContent).toContain('document (local JSON/JDBC)');
    expect(fixture.nativeElement.textContent).toContain('picketlink-realm-config.json');
  });

  it('saves scim provider settings', () => {
    const component = fixture.componentInstance;
    const state = component.config();
    if (!state) {
      throw new Error('expected config');
    }
    state.provider = 'scim';
    state.useDefaultBaseUrl = false;
    state.scimBaseUrl = 'http://127.0.0.1:9999/scim';
    component.save();

    const req = httpMock.expectOne((request) => request.method === 'POST');
    expect(req.request.params.get('provider')).toBe('scim');
    req.flush({ ...configState, provider: 'scim', effectiveScimBaseUrl: 'http://127.0.0.1:9999/scim' });
    fixture.detectChanges();

    expect(fixture.nativeElement.textContent).toContain('Provider settings saved');
  });
});
