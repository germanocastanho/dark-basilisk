/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

import { expect, test } from "bun:test";
import {
  checkScope,
  extractTargetHost,
  hostInScope,
} from "../../src/policy/scope.ts";

test("empty scope allows every host", () => {
  expect(hostInScope("evil.example", [])).toBe(true);
});

test("exact host matches", () => {
  expect(hostInScope("example.com", ["example.com"])).toBe(true);
});

test("subdomain matches its parent entry", () => {
  expect(hostInScope("api.example.com", ["example.com"])).toBe(true);
});

test("sibling host is rejected", () => {
  expect(hostInScope("notexample.com", ["example.com"])).toBe(false);
});

test("IPv4 CIDR match", () => {
  expect(hostInScope("10.0.1.5", ["10.0.0.0/16"])).toBe(true);
});

test("IPv4 CIDR miss", () => {
  expect(hostInScope("10.1.1.5", ["10.0.0.0/16"])).toBe(false);
});

test("extracts host from url", () => {
  expect(extractTargetHost({ url: "https://Example.com:8443/x" })).toBe(
    "example.com",
  );
});

test("extracts host from base_url", () => {
  expect(extractTargetHost({ base_url: "api.example.com:443" })).toBe(
    "api.example.com",
  );
});

test("extracts host from domain", () => {
  expect(extractTargetHost({ domain: "example.com" })).toBe("example.com");
});

test("target-reaching tool refused when out of scope", () => {
  const v = checkScope("http_fetch", { url: "https://evil.example/" }, [
    "example.com",
  ]);
  expect(v.allowed).toBe(false);
  expect(v.host).toBe("evil.example");
  expect(v.reason).toContain("outside the configured scope");
});

test("target-reaching tool allowed when in scope", () => {
  const v = checkScope("http_fetch", { url: "https://api.example.com/" }, [
    "example.com",
  ]);
  expect(v.allowed).toBe(true);
});

test("every red-team probe that reaches the target is scope-gated", () => {
  for (const name of [
    "command_injection_probe",
    "path_traversal_probe",
    "xxe_probe",
    "ssti_probe",
    "xpath_injection_probe",
    "ldap_injection_probe",
    "deserialization_probe",
    "auth_bypass_probe",
  ]) {
    const v = checkScope(name, { url: "https://evil.example/?id=1" }, [
      "example.com",
    ]);
    expect(v.allowed).toBe(false);
    expect(v.host).toBe("evil.example");
  }
});

test("non-target-reaching tool always allowed", () => {
  const v = checkScope("dns_lookup", { domain: "evil.example" }, [
    "example.com",
  ]);
  expect(v.allowed).toBe(true);
});

test("run_command is exempt from scope", () => {
  const v = checkScope(
    "run_command",
    { command: "curl https://evil.example" },
    ["example.com"],
  );
  expect(v.allowed).toBe(true);
});

test("IPv6 CIDR match", () => {
  expect(hostInScope("2001:db8::5", ["2001:db8::/32"])).toBe(true);
});

test("IPv6 CIDR miss", () => {
  expect(hostInScope("2001:dead::5", ["2001:db8::/32"])).toBe(false);
});

test("IPv6 exact match across notations", () => {
  expect(hostInScope("::1", ["0:0:0:0:0:0:0:1"])).toBe(true);
});

test("IPv4 host is not matched by an IPv6 CIDR", () => {
  expect(hostInScope("10.0.0.1", ["2001:db8::/32"])).toBe(false);
});

test("extracts IPv6 host from a bracketed url", () => {
  expect(extractTargetHost({ url: "http://[2001:db8::1]:8443/x" })).toBe(
    "2001:db8::1",
  );
});

test("extracts a bare IPv6 literal from host", () => {
  expect(extractTargetHost({ host: "2001:DB8::1" })).toBe("2001:db8::1");
});

test("target-reaching tool refused for out-of-scope IPv6", () => {
  const v = checkScope("tcp_scan", { host: "2001:dead::1" }, ["2001:db8::/32"]);
  expect(v.allowed).toBe(false);
  expect(v.host).toBe("2001:dead::1");
});
