export interface ClientRegistrationRequest {
  clientId: string;
  clientSecret?: string;
  scopes: string[];
  tokenEndpointAuthMethod: string;
}

export interface ClientRegistrationView {
  clientId: string;
  clientSecret: string;
  scopes: string[];
  tokenEndpointAuthMethod: string;
}
