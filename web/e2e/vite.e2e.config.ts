// Vite config for the wallet-login e2e harness. Serves e2e/harness.html as the
// root and proxies /v1/iam/* to the local IAM backend on :8000 so the harness
// hits the REAL server flow same-origin (the production WalletConnect.tsx builds
// /v1/iam/web3/* paths and relies on them being same-origin).
//
// The ONLY source rewrite is aliasing ../Setting to e2e/setting-shim.ts: that
// module pulls in the entire admin UI, and WalletConnect.tsx needs just two of
// its symbols (goToLink, showMessage). WalletConnect.tsx itself — the code under
// test — is imported and run unmodified.
import {defineConfig} from "vite";
import react from "@vitejs/plugin-react";
import {fileURLToPath} from "node:url";
import {dirname, resolve} from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const IAM_BACKEND = process.env.IAM_BACKEND || "http://localhost:8000";
const SHIM = resolve(here, "setting-shim.ts");
const REAL_SETTING = resolve(here, "../src/Setting"); // no ext; matches Setting.tsx

// Redirect every import of web/src/Setting(.tsx) to the 2-symbol shim. A
// resolveId hook is used (not a string alias) so it catches BOTH the bare
// "../Setting" specifier from WalletConnect.tsx AND any already-resolved
// absolute path the dep scanner produces. This is the only source rewrite:
// WalletConnect.tsx — the code under test — runs unmodified.
function aliasSettingPlugin() {
  return {
    name: "e2e-alias-setting",
    enforce: "pre" as const,
    resolveId(source: string, importer: string | undefined) {
      if (source === SHIM) return null;
      const isBareSetting = source === "../Setting" || source.endsWith("/src/Setting") || source.endsWith("/src/Setting.tsx");
      const resolvesToReal =
        importer != null && (source === "../Setting") && importer.includes("/src/auth/");
      if (isBareSetting || resolvesToReal || source === REAL_SETTING || source === `${REAL_SETTING}.tsx`) {
        return SHIM;
      }
      return null;
    },
  };
}

export default defineConfig({
  root: here,
  plugins: [aliasSettingPlugin(), react()],
  server: {
    port: 7100,
    strictPort: true,
    proxy: {
      "/v1/iam": {target: IAM_BACKEND, changeOrigin: true},
    },
  },
  define: {
    "process.env": "{}",
    global: "globalThis",
  },
});
