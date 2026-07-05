import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

export interface ConfigurationProfile {
  id: string;
  title: string;
  description: string;
  mutatesStandaloneXml: boolean;
  requiresWildFlyModule: boolean;
}

export interface ApplyConfigurationResult {
  profileId: string;
  standaloneXml: string;
  backupPath: string;
  backupFile: string;
  changed: boolean;
  restartRequired: boolean;
  httpsListenersRemoved: number;
  requiresWildFlyModule: boolean;
  deployerHandoffNote: string;
  messages: string[];
}

@Injectable({ providedIn: 'root' })
export class StandaloneConfigService {
  constructor(private readonly http: HttpClient) {}

  listProfiles(): Observable<ConfigurationProfile[]> {
    return this.http.get<ConfigurationProfile[]>('../api/idm/standalone/profiles');
  }

  applyProfile(profileId: string, jbossHome: string, removeHttpsListener: boolean) {
    const params = new HttpParams()
      .set('profile', profileId)
      .set('jbossHome', jbossHome)
      .set('removeHttpsListener', String(removeHttpsListener));
    return this.http.post<ApplyConfigurationResult>(
      '../api/idm/standalone/apply',
      null,
      { params },
    );
  }
}
