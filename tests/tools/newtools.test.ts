/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
} from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { boundedPool, parseHttpUrl } from "../../src/tools/http.ts";
import { jwtInspect } from "../../src/tools/jwt.ts";
import {
  commandInjectionProbe,
  pathTraversalProbe,
  xxeProbe,
} from "../../src/tools/exploitation.ts";
import { sstiProbe } from "../../src/tools/templating.ts";
import {
  xpathInjectionProbe,
  ldapInjectionProbe,
} from "../../src/tools/queryInjection.ts";
import { deserializationProbe } from "../../src/tools/deserialization.ts";
import { authBypassProbe } from "../../src/tools/access.ts";
import { oobStart, oobPoll, oobStop } from "../../src/tools/oob.ts";
import { sigmaGenerate, logTriage, iocCheck } from "../../src/tools/defense.ts";
import { dispatch, listTools } from "../../src/tools/registry.ts";
import type { ToolContext } from "../../src/tools/types.ts";
import type { Config } from "../../src/engine/config.ts";
import type { Finding, FindingsStore } from "../../src/engine/findings.ts";
import { DEFAULT_MODEL } from "../../src/engine/model.ts";

const noopFindings: FindingsStore = {
  path: "/dev/null",
  list: () => [],
  record: (input) => ({ id: "F-1", createdAt: "", ...input }) as Finding,
};

function makeCtx(workdir: string, scope: string[] = []): ToolContext {
  const config: Config = {
    model: DEFAULT_MODEL,
    commandTimeoutMs: 1000,
    allowedCommands: [],
    scope,
    mcpServers: [],
  };
  return { workdir, confirm: async () => true, config, findings: noopFindings };
}

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

describe("http helpers", () => {
  test("parseHttpUrl accepts http(s) and rejects others", () => {
    expect(parseHttpUrl("https://a.example/x")?.hostname).toBe("a.example");
    expect(parseHttpUrl("http://a.example")?.protocol).toBe("http:");
    expect(parseHttpUrl("ftp://a.example")).toBeNull();
    expect(parseHttpUrl("not a url")).toBeNull();
    expect(parseHttpUrl(42)).toBeNull();
  });

  test("boundedPool preserves order and caps concurrency", async () => {
    let active = 0;
    let peak = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);
    const out = await boundedPool(items, 4, async (n) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5));
      active -= 1;
      return n * 2;
    });
    expect(out).toEqual(items.map((n) => n * 2));
    expect(peak).toBeLessThanOrEqual(4);
  });
});

describe("jwt_inspect", () => {
  test("flags alg=none", async () => {
    const token = `${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub: "1" })}.`;
    const out = await jwtInspect.run({ token }, makeCtx("/tmp"));
    expect(out.content).toContain("alg=none");
    expect(out.content).toContain("no `exp`");
  });

  test("cracks a weak HS256 secret", async () => {
    const h = b64url({ alg: "HS256", typ: "JWT" });
    const p = b64url({ sub: "admin", exp: 9999999999 });
    const sig = createHmac("sha256", "secret")
      .update(`${h}.${p}`)
      .digest("base64url");
    const out = await jwtInspect.run(
      { token: `${h}.${p}.${sig}` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain('CRACKED: "secret"');
  });

  test("rejects a non-JWT", async () => {
    const out = await jwtInspect.run({ token: "nope" }, makeCtx("/tmp"));
    expect(out.isError).toBe(true);
  });
});

describe("sigma_generate", () => {
  test("emits a YAML rule with the given fields", async () => {
    const out = await sigmaGenerate.run(
      {
        title: "Suspicious login",
        product: "linux",
        service: "sshd",
        selection: { "message|contains": "Failed password" },
        level: "high",
      },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("title: Suspicious login");
    expect(out.content).toContain("level: high");
    expect(out.content).toContain("Failed password");
    expect(out.content).toContain("condition: selection");
  });
});

describe("log_triage", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "basilisk-log-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test("detects attack signatures in a log file", async () => {
    writeFileSync(
      join(dir, "access.log"),
      [
        '10.0.0.1 - - "GET /?q=1 UNION SELECT password FROM users"',
        '10.0.0.2 - - "GET / HTTP/1.1" 200 "-" "sqlmap/1.7"',
        "10.0.0.3 - - normal request",
      ].join("\n"),
    );
    const out = await logTriage.run({ path: "access.log" }, makeCtx(dir));
    expect(out.content).toContain("SQLi");
    expect(out.content).toContain("Scanner UA");
  });

  test("refuses paths outside the workdir", async () => {
    const out = await logTriage.run({ path: "../../etc/passwd" }, makeCtx(dir));
    expect(out.isError).toBe(true);
  });
});

describe("ioc_check", () => {
  test("classifies hashes and domains without network", async () => {
    const out = await iocCheck.run(
      {
        indicators: ["a".repeat(64), "b".repeat(32), "evil.example"],
      },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("sha256");
    expect(out.content).toContain("md5");
    expect(out.content).toContain("domain");
  });
});

describe("active exploitation probes", () => {
  let server: ReturnType<typeof Bun.serve>;
  let base: string;

  beforeAll(() => {
    server = Bun.serve({
      port: 0,
      async fetch(req) {
        const url = new URL(req.url);
        const q = url.searchParams.get("q") ?? "";
        switch (url.pathname) {
          case "/cmd":
            if (/\bid\b/.test(q)) {
              return new Response("uid=0(root) gid=0(root) groups=0(root)\n");
            }
            return new Response(`ok ${q}`);
          case "/safe":
            return new Response(`you said ${q}`);
          case "/lfi": {
            const file = url.searchParams.get("file") ?? "";
            return file.includes("passwd")
              ? new Response("root:x:0:0:root:/root:/bin/bash\n")
              : new Response("not found", { status: 404 });
          }
          case "/xml": {
            const body = await req.text();
            return body.includes('SYSTEM "file:///etc/passwd"')
              ? new Response("<data>root:x:0:0:root:/root:/bin/bash</data>")
              : new Response("<data/>");
          }
          case "/ssti": {
            const m = q.match(/(\d+)\*(\d+)/);
            return new Response(
              m ? `result: ${Number(m[1]) * Number(m[2])}` : `echo ${q}`,
            );
          }
          case "/xpath":
            if (q.includes("'1'='1")) return new Response("x".repeat(200));
            if (q.includes("'1'='2")) return new Response("");
            return new Response(`record:${q}`);
          case "/ldap":
            if (q === "*") return new Response("u".repeat(200));
            return new Response(`user:${q}`);
          case "/deser":
            return new Response("dashboard", {
              headers: { "set-cookie": "session=rO0ABXNyABZq; Path=/" },
            });
          case "/admin":
            return req.headers.get("x-forwarded-for") === "127.0.0.1"
              ? new Response("secret panel")
              : new Response("denied", { status: 401 });
          default:
            return new Response("nope", { status: 404 });
        }
      },
    });
    base = `http://localhost:${server.port}`;
  });
  afterAll(() => server.stop(true));

  test("command_injection_probe flags an executing endpoint", async () => {
    const out = await commandInjectionProbe.run(
      { url: `${base}/cmd?q=1` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("[!]");
    expect(out.content).toContain("output-based");
  });

  test("command_injection_probe stays quiet on a safe endpoint", async () => {
    const out = await commandInjectionProbe.run(
      { url: `${base}/safe?q=1` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("No command-injection indicators");
  });

  test("path_traversal_probe detects a leaked passwd file", async () => {
    const out = await pathTraversalProbe.run(
      { url: `${base}/lfi?file=index` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("[!]");
    expect(out.content).toContain("/etc/passwd");
  });

  test("path_traversal_probe stays quiet without a leak", async () => {
    const out = await pathTraversalProbe.run(
      { url: `${base}/safe?q=1` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("No traversal indicators");
  });

  test("xxe_probe detects classic external-entity file disclosure", async () => {
    const out = await xxeProbe.run({ url: `${base}/xml` }, makeCtx("/tmp"));
    expect(out.content).toContain("classic XXE");
  });

  test("xxe_probe stays quiet when the entity is not resolved", async () => {
    const out = await xxeProbe.run({ url: `${base}/safe` }, makeCtx("/tmp"));
    expect(out.content).toContain("No XXE indicators");
  });

  test("ssti_probe detects a rendered expression", async () => {
    const out = await sstiProbe.run(
      { url: `${base}/ssti?q=1` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("[!]");
    expect(out.content).toContain("rendered");
  });

  test("ssti_probe stays quiet when the expression is reflected raw", async () => {
    const out = await sstiProbe.run(
      { url: `${base}/safe?q=1` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("No template evaluation");
  });

  test("xpath_injection_probe flags a boolean divergence", async () => {
    const out = await xpathInjectionProbe.run(
      { url: `${base}/xpath?q=1` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("boolean-based");
  });

  test("ldap_injection_probe flags a wildcard divergence", async () => {
    const out = await ldapInjectionProbe.run(
      { url: `${base}/ldap?q=1` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("wildcard divergence");
  });

  test("deserialization_probe surfaces a serialized cookie", async () => {
    const out = await deserializationProbe.run(
      { url: `${base}/deser` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("Java serialized");
    expect(out.content).toContain("cookie");
  });

  test("auth_bypass_probe flags a header bypass", async () => {
    const out = await authBypassProbe.run(
      { url: `${base}/admin` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("[!]");
    expect(out.content).toContain("X-Forwarded-For");
  });

  test("auth_bypass_probe reports nothing to bypass on an open resource", async () => {
    const out = await authBypassProbe.run(
      { url: `${base}/safe` },
      makeCtx("/tmp"),
    );
    expect(out.content).toContain("not access-controlled");
  });
});

describe("out-of-band listener", () => {
  afterAll(async () => {
    await oobStop.run({}, makeCtx("/tmp"));
  });

  test("captures a callback and reports it", async () => {
    const start = await oobStart.run({ host: "localhost" }, makeCtx("/tmp"));
    const url = start.content.match(/Callback URL: (\S+)/)?.[1];
    expect(url).toBeDefined();
    await fetch(url!);
    const poll = await oobPoll.run({ clear: true }, makeCtx("/tmp"));
    expect(poll.content).toContain("OOB interaction");
    expect(poll.content).toContain("GET");
  });

  test("ignores a request that doesn't carry the callback token", async () => {
    const start = await oobStart.run({ host: "localhost" }, makeCtx("/tmp"));
    const url = start.content.match(/Callback URL: (\S+)/)?.[1];
    const listener = new URL(url!);
    await fetch(`${listener.origin}/unrelated-path`);
    const poll = await oobPoll.run({ clear: true }, makeCtx("/tmp"));
    expect(poll.content).toContain("No interactions");
  });
});

describe("registry wiring for new tools", () => {
  test("offensive probes are registered and gated", () => {
    const tools = new Map(listTools().map((t) => [t.name, t]));
    for (const name of [
      "sqli_probe",
      "xss_probe",
      "ssrf_probe",
      "idor_probe",
      "credential_spray",
      "graphql_introspect",
      "command_injection_probe",
      "path_traversal_probe",
      "xxe_probe",
      "ssti_probe",
      "xpath_injection_probe",
      "ldap_injection_probe",
      "deserialization_probe",
      "auth_bypass_probe",
    ]) {
      expect(tools.get(name)?.risky).toBe(true);
    }
    // Offline tools stay open.
    expect(tools.get("jwt_inspect")?.risky).toBe(false);
    expect(tools.get("sigma_generate")?.risky).toBe(false);
  });

  test("sqli_probe is scope-guarded before the approval gate", async () => {
    let confirmed = false;
    const ctx: ToolContext = {
      ...makeCtx("/tmp", ["example.com"]),
      confirm: async () => {
        confirmed = true;
        return true;
      },
    };
    const out = await dispatch(
      "sqli_probe",
      { url: "https://evil.example/?id=1" },
      ctx,
    );
    expect(out.isError).toBe(true);
    expect(out.content).toContain("outside the configured scope");
    expect(confirmed).toBe(false);
  });
});
