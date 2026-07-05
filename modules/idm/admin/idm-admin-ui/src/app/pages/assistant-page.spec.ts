import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { AssistantPage } from './assistant-page';

describe('AssistantPage', () => {
  let fixture: ComponentFixture<AssistantPage>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AssistantPage],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(AssistantPage);
    fixture.detectChanges();
    httpMock.expectOne('../api/idm/standalone/profiles').flush([
      {
        id: 'SAML',
        title: 'SAML SP',
        description: 'SAML service provider profile',
        mutatesStandaloneXml: true,
        requiresWildFlyModule: true,
      },
    ]);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('renders the configuration assistant heading', () => {
    expect(fixture.nativeElement.textContent).toContain('Configuration assistant');
  });

  it('applies the selected profile', () => {
    const jbossHomeInput = fixture.nativeElement.querySelector(
      'input[placeholder="/opt/wildfly-36"]',
    ) as HTMLInputElement;
    jbossHomeInput.value = '/opt/wildfly';
    jbossHomeInput.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    const applyButton = fixture.nativeElement.querySelector('button') as HTMLButtonElement;
    applyButton.click();

    const req = httpMock.expectOne(
      (request) =>
        request.url === '../api/idm/standalone/apply' &&
        request.params.get('profile') === 'SAML' &&
        request.params.get('jbossHome') === '/opt/wildfly',
    );
    req.flush({
      profileId: 'SAML',
      standaloneXml: '<server/>',
      backupPath: '/tmp',
      backupFile: 'standalone.xml.bak',
      changed: true,
      restartRequired: true,
      httpsListenersRemoved: 0,
      requiresWildFlyModule: true,
      deployerHandoffNote: 'Restart WildFly',
      messages: ['Applied SAML profile'],
    });
    fixture.detectChanges();

    expect(fixture.nativeElement.textContent).toContain('Applied SAML profile');
    expect(fixture.nativeElement.textContent).toContain('Restart required');
  });
});
