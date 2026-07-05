import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ClientRegistryPage } from './client-registry-page';

describe('ClientRegistryPage', () => {
  let fixture: ComponentFixture<ClientRegistryPage>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ClientRegistryPage],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ClientRegistryPage);
    fixture.detectChanges();
    httpMock.expectOne('/api/auth/clients').flush([]);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('renders the registration heading', () => {
    const heading = fixture.nativeElement.querySelector('h1');
    expect(heading?.textContent).toContain('OAuth Client Registration');
  });

  it('shows an empty client list message', () => {
    expect(fixture.nativeElement.textContent).toContain('No clients registered yet.');
  });

  it('issues a delete request when remove is clicked', async () => {
    const localFixture = TestBed.createComponent(ClientRegistryPage);
    localFixture.detectChanges();
    httpMock.expectOne('/api/auth/clients').flush([
      {
        clientId: 'demo-client',
        clientSecret: 'secret',
        scopes: ['api.read'],
        tokenEndpointAuthMethod: 'client_secret_basic',
      },
    ]);
    localFixture.detectChanges();
    await localFixture.whenStable();
    localFixture.detectChanges();

    const deleteButton = localFixture.nativeElement.querySelector('button.danger') as HTMLButtonElement;
    deleteButton.click();

    const deleteReq = httpMock.expectOne('/api/auth/clients/demo-client');
    expect(deleteReq.request.method).toBe('DELETE');
    deleteReq.flush(null);
  });
});
