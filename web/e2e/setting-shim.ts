// Minimal stand-in for ../Setting, used ONLY by the e2e harness via a Vite
// alias. WalletConnect.tsx imports exactly two symbols from Setting —
// goToLink and showMessage — both trivial navigation/toast helpers. Stubbing
// just these keeps WalletConnect.tsx's real logic (connect -> nonce -> sign ->
// verify -> redirect) running unmodified while avoiding bundling the entire
// app (Setting.tsx pulls in the whole admin UI). Everything that matters for
// the proof — the server flow — is untouched.
//
// We record the calls on window so the harness/spec can observe the success
// signal (goToLink for a redirect payload) or an error (showMessage).

interface SettingEvent {
  kind: "goToLink" | "showMessage";
  arg1: string;
  arg2?: string;
  at: number;
}

declare global {
  interface Window {
    __settingEvents?: SettingEvent[];
  }
}

function record(ev: SettingEvent): void {
  if (!window.__settingEvents) {
    window.__settingEvents = [];
  }
  window.__settingEvents.push(ev);
}

export function goToLink(link: string): void {
  record({kind: "goToLink", arg1: link, at: Date.now()});
  // Do NOT actually navigate in the harness — we want to keep the page so the
  // spec can read the success state. Real prod navigates; here the recorded
  // event IS the success signal. (For app-hanzo signup the success payload is a
  // user id string, not an http URL, so prod would window.location.reload();
  // the harness intercepts reload separately.)
}

export function showMessage(type: string, text: string): void {
  record({kind: "showMessage", arg1: type, arg2: text, at: Date.now()});
  // Surface to console so failures are visible in Playwright's console capture.
  // eslint-disable-next-line no-console
  console.log(`[showMessage:${type}] ${text}`);
}
