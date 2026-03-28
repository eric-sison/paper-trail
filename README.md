# paper-trail

A monorepo for PDF signing with PAdES-B-LT compliance. Built with TanStack Start, Hono, and a custom PDF signing library backed by PNPKI certificates.

## Structure

```
paper-trail/
├── apps/
│   ├── web/          # TanStack Start frontend (port 3000)
│   └── api/          # Hono REST API (port 3852)
└── packages/
    ├── pdf-signer/   # PDF signing library (PAdES-B-LT)
    └── ui/           # Shared UI components (shadcn/ui)
```

## Requirements

- Node.js >= 20
- pnpm 9.15.9

## Installation

Clone the repository and install dependencies from the root:

```bash
git clone <repository-url>
cd paper-trail
pnpm install
```

## Development

Start all apps and packages in development mode:

```bash
pnpm dev
```

Or run individual apps:

```bash
# Frontend only
cd apps/web
pnpm dev

# API only
cd apps/api
pnpm dev
```

The web app runs on `http://localhost:3000` and the API on `http://localhost:3852`.

## Building

Build all packages and apps:

```bash
pnpm build
```

Packages are built in dependency order — `pdf-signer` is built before the apps that depend on it.

## Testing

Run tests for the `pdf-signer` package:

```bash
cd packages/pdf-signer
pnpm test
```

For verbose output showing all test names:

```bash
pnpm test:verbose
```

For watch mode during development:

```bash
pnpm test:watch
```

## Adding UI Components

To add shadcn/ui components, run the following from the root:

```bash
pnpm dlx shadcn@latest add <component> -c apps/web
```

Components are placed in `packages/ui/src/components/` and can be imported in the web app:

```tsx
import { Button } from "@workspace/ui/components/button";
```

## Other Commands

```bash
pnpm lint        # Lint all packages
pnpm typecheck   # Type-check all packages
pnpm format      # Format all files with Prettier
```
