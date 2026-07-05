import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { UsersPage } from './users-page';

const realmState = {
  documentId: 'picketlink-idm-realm',
  version: 1,
  provider: 'document',
  roles: ['role1'],
  groups: [],
  users: [{ id: 'u1', loginName: 'alice', enabled: true, roles: ['role1'] }],
};

describe('UsersPage', () => {
  let fixture: ComponentFixture<UsersPage>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UsersPage],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(UsersPage);
    fixture.detectChanges();
    httpMock.expectOne('../api/idm/realm/users').flush(realmState);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('renders realm users from the API', () => {
    expect(fixture.nativeElement.textContent).toContain('alice');
    expect(fixture.nativeElement.textContent).toContain('Document version: 1');
  });

  it('creates a user and updates the realm version', () => {
    const component = fixture.componentInstance;
    component.loginName = 'bob';
    component.password = 'secret';
    component.roles = 'role1';
    component.createUser();

    const req = httpMock.expectOne(
      (request) => request.method === 'POST' && request.params.get('loginName') === 'bob',
    );
    req.flush({ ...realmState, version: 2, users: [...realmState.users, { id: 'u2', loginName: 'bob', enabled: true, roles: ['role1'] }] });
    fixture.detectChanges();

    expect(fixture.nativeElement.textContent).toContain('User created.');
    expect(fixture.nativeElement.textContent).toContain('Document version: 2');
  });

  it('deletes a user', () => {
    fixture.componentInstance.removeUser('u1');

    const req = httpMock.expectOne(
      (request) => request.method === 'DELETE' && request.params.get('userId') === 'u1',
    );
    req.flush({ ...realmState, version: 2, users: [] });
    fixture.detectChanges();

    expect(fixture.nativeElement.textContent).toContain('User deleted.');
  });
});
