/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { render } from "ink";
import { App, type AppProps } from "./App.tsx";

/**
 * Mount the Ink chat app and resolve when the operator ends the session.
 * Keeping the render bootstrap here leaves `cli.ts` free of JSX and
 * purely command wiring.
 */
export async function startChat(params: AppProps): Promise<void> {
  const { waitUntilExit } = render(<App {...params} />);
  await waitUntilExit();
}
