import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { AdminComponent } from './admin.component';

describe('AdminComponent', () => {
  let fixture: ComponentFixture<AdminComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AdminComponent],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(AdminComponent);
    fixture.detectChanges();

    httpMock.expectOne('../api/info').flush({ name: 'oidc-as' });
    httpMock.expectOne('../api/keys').flush({ keys: [] });
    httpMock.expectOne('../api/idm/realm/users').flush({
      documentId: 'picketlink-idm-realm',
      version: 1,
      users: [],
    });
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('renders the admin dashboard heading', () => {
    expect(fixture.nativeElement.textContent).toContain('OIDC Authorization Server Admin');
  });

  it('rotates the signing key', async () => {
    fixture.componentInstance.rotate();

    const rotateReq = httpMock.expectOne('../api/keys/rotate?validityDays=365');
    expect(rotateReq.request.method).toBe('POST');
    rotateReq.flush({ activeAlias: 'oidc-signing-2', generation: 2 });

    fixture.detectChanges();
    const refreshKeysReq = httpMock.expectOne('../api/keys');
    refreshKeysReq.flush({ keys: [{ alias: 'oidc-signing-2' }] });
    fixture.detectChanges();
    await fixture.whenStable();

    expect(fixture.nativeElement.textContent).toContain('Rotated active alias to oidc-signing-2');
  });
});
