# AngularAuthUi

This project was generated using [Angular CLI](https://github.com/angular/angular-cli) version 22.0.5.

Angular 22 requires Node.js `^22.22.3`, `^24.15.0`, or `^26.0.0`. Use `.nvmrc` locally (`nvm use`) or run Volta setup:

```bash
../scripts/volta-init.sh
```

The Maven build installs Node `v22.22.3` via `frontend-maven-plugin` when Volta/nvm are not used.

## UI stack (Angular 22 maintained APIs)

- **Signal Forms** (`@angular/forms/signals`) instead of deprecated template-driven `ngModel`
- **`httpResource`** for client list loading instead of manual `subscribe`/`HttpClient.get`
- **`provideHttpClient()`** with Fetch backend (default in Angular 22; `withFetch()` is deprecated)
- **`ChangeDetectionStrategy.OnPush`** on components (Angular 22 default)

## npm warnings

| Warning | Status |
| --- | --- |
| `EBADENGINE` (Node `<22.22.3`) | Upgrade Node locally or use `nvm use` / Maven build |
| `allow-scripts` | Resolved via `allowScripts` in `package.json` |
| `@babel/core` audit (dev-only, via `@angular/build`) | Low severity; wait for upstream Angular patch |
| `esbuild` audit | Mitigated with npm `overrides` to `0.28.1` |

## Development server

To start a local development server, run:

```bash
ng serve
```

Once the server is running, open your browser and navigate to `http://localhost:4200/`. The application will automatically reload whenever you modify any of the source files.

## Code scaffolding

Angular CLI includes powerful code scaffolding tools. To generate a new component, run:

```bash
ng generate component component-name
```

For a complete list of available schematics (such as `components`, `directives`, or `pipes`), run:

```bash
ng generate --help
```

## Building

To build the project run:

```bash
ng build
```

This will compile your project and store the build artifacts in the `dist/` directory. By default, the production build optimizes your application for performance and speed.

## Running unit tests

To execute unit tests with the [Vitest](https://vitest.dev/) test runner, use the following command:

```bash
ng test
```

## Running end-to-end tests

For end-to-end (e2e) testing, run:

```bash
ng e2e
```

Angular CLI does not come with an end-to-end testing framework by default. You can choose one that suits your needs.

## Additional Resources

For more information on using the Angular CLI, including detailed command references, visit the [Angular CLI Overview and Command Reference](https://angular.dev/tools/cli) page.
