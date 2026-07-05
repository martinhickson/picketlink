import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { httpResource } from '@angular/common/http';
import { form, FormField, required, submit } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { ClientRegistrationService } from '../services/client-registration.service';
import {
  ClientRegistrationRequest,
  ClientRegistrationView,
} from '../models/client-registration';

interface ClientRegistrationFormModel {
  clientId: string;
  clientSecret: string;
  scopesText: string;
  tokenEndpointAuthMethod: string;
  generateSecret: boolean;
}

@Component({
  selector: 'app-client-registry-page',
  imports: [FormField],
  templateUrl: './client-registry-page.html',
  styleUrl: './client-registry-page.css',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ClientRegistryPage {
  private readonly clientService = inject(ClientRegistrationService);

  protected readonly createdSecret = signal<string | null>(null);
  protected readonly actionError = signal<string | null>(null);

  protected readonly clientsResource = httpResource<ClientRegistrationView[]>(
    () => '/api/auth/clients',
    { defaultValue: [] },
  );

  protected readonly clients = computed(() => this.clientsResource.value());
  protected readonly loading = computed(() => this.clientsResource.isLoading());
  protected readonly loadError = computed(() => this.clientsResource.error()?.message ?? null);

  protected readonly registrationModel = signal<ClientRegistrationFormModel>({
    clientId: '',
    clientSecret: '',
    scopesText: 'api.read',
    tokenEndpointAuthMethod: 'client_secret_basic',
    generateSecret: true,
  });

  protected readonly registrationForm = form(this.registrationModel, (path) => {
    required(path.clientId, { message: 'Client ID is required' });
  });

  protected refreshClients() {
    this.clientsResource.reload();
  }

  protected onSubmit(event: Event) {
    event.preventDefault();
    this.actionError.set(null);
    this.createdSecret.set(null);

    submit(this.registrationForm, async () => {
      const model = this.registrationModel();
      const request: ClientRegistrationRequest = {
        clientId: model.clientId.trim(),
        scopes: model.scopesText
          .split(/[\s,]+/)
          .map((scope) => scope.trim())
          .filter((scope) => scope.length > 0),
        tokenEndpointAuthMethod: model.tokenEndpointAuthMethod,
      };

      if (!model.generateSecret && model.clientSecret.trim()) {
        request.clientSecret = model.clientSecret.trim();
      }

      try {
        const created = await firstValueFrom(this.clientService.registerClient(request));
        this.createdSecret.set(created.clientSecret);
        this.registrationModel.set({
          clientId: '',
          clientSecret: '',
          scopesText: 'api.read',
          tokenEndpointAuthMethod: 'client_secret_basic',
          generateSecret: true,
        });
        this.clientsResource.reload();
      } catch (err: unknown) {
        const error = err as { error?: { error_description?: string; error?: string } };
        const message =
          error?.error?.error_description ??
          error?.error?.error ??
          'Unable to register client.';
        this.actionError.set(message);
      }
    });
  }

  protected deleteClient(clientId: string) {
    this.actionError.set(null);
    this.clientService.deleteClient(clientId).subscribe({
      next: () => this.clientsResource.reload(),
      error: () => this.actionError.set(`Unable to delete client ${clientId}.`),
    });
  }
}
