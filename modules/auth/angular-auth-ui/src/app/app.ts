import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  template: '<router-outlet />',
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [
    `
      :host {
        display: block;
        min-height: 100vh;
        background: #f4f6fb;
        color: #1f2937;
        font-family:
          Inter,
          system-ui,
          -apple-system,
          sans-serif;
      }
    `,
  ],
})
export class App {}
