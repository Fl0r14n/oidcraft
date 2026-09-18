/// <reference types="vite/client" />

// Deliberately no `ImportMetaEnv` augmentation: this app reads configuration through `src/env.ts` as
// whole `process.env.OIDCRAFT_PUBLIC_*` literals, never through `import.meta.env` (ARCHITECTURE.md §9.1).
