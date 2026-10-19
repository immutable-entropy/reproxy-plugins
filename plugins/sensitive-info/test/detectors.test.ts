import { describe, it, expect } from "reproxy/testing";
import { CATALOG, scan, type Input, type Options } from "../src/detectors";

const base: Options = {
  detectors: [],
  skip: [],
  minEntropy: 3.5,
  maxBody: 1 << 20,
  maxPii: 1 << 20,
  ignoreValues: [],
  hexHashes: false,
  maxHits: 100,
};

/** found scans a side of an exchange and returns "detector=value" strings. */
function found(input: Partial<Input>, opts: Partial<Options> = {}): string[] {
  const full: Input = { side: input.side ?? "request", head: input.head, query: input.query, body: input.body };
  return scan(full, { ...base, ...opts }).map((h) => `${h.detector}=${h.value}`);
}

function body(text: string, opts: Partial<Options> = {}): string[] {
  return found({ side: "response", body: text }, opts);
}

describe("passwords and user names", () => {
  it("finds both in a form login", () => {
    const got = found({ body: "username=ann%40corp.test&password=hunter2&remember=1" });
    expect(got).toContain("field_password=hunter2");
    expect(got).toContain("field_username=ann@corp.test");
  });

  it("finds both in a JSON login", () => {
    const got = found({ body: `{"user": "bob", "newPassword": "s3cr3t!"}` });
    expect(got).toContain("field_password=s3cr3t!");
    expect(got).toContain("field_username=bob");
  });

  it("finds both in a multipart login", () => {
    const part = [
      "--x",
      'Content-Disposition: form-data; name="username"',
      "",
      "carol",
      "--x",
      'Content-Disposition: form-data; name="password"',
      "",
      "letmein",
      "--x--",
    ].join("\r\n");
    const got = found({ body: part });
    expect(got).toContain("field_password=letmein");
    expect(got).toContain("field_username=carol");
  });

  it("finds a password in an XML body", () => {
    expect(found({ body: "<login><user>dave</user><password>sesame</password></login>" })).toContain("field_password=sesame");
  });

  it("finds a password in a query string", () => {
    expect(found({ query: "user=erin&password=p4ssw0rd" })).toContain("field_password=p4ssw0rd");
  });

  it("ignores masked and absent values", () => {
    expect(body(`{"password":"********","passwd":null,"pass":"{{secret}}"}`)).toEqual([]);
  });

  it("ignores names that only talk about passwords", () => {
    expect(body(`{"password_strength":"weak","has_password":true,"passwordPolicy":"8 chars"}`)).toEqual([]);
  });

  it("doesn't report a user name with no credential beside it", () => {
    expect(body(`{"username":"frank"}`)).toEqual([]);
    expect(found({ side: "request", body: `{"username":"frank"}` })).toEqual([]);
  });
});

describe("hashes", () => {
  it("finds a bcrypt hash", () => {
    const h = "$2y$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123456";
    expect(body(`{"stored":"${h.slice(0, 60)}"}`)[0]).toBe("bcrypt_hash=" + h.slice(0, 60));
  });

  it("finds crypt(3), Argon2 and Django hashes", () => {
    const got = body(
      [
        "$6$rounds=656000$saltsalt$QHXbCUdCbkMcJIaeFrh6F1aL5mWjqA7HCPFbVZcBDbTbqFN0WYQxX4N4vUbTgpeeVoMA0kj0EqxOkwTK7w0zB0",
        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        "pbkdf2_sha256$600000$abcDEF123$FGhIjKlMnOpQrStUvWxYz0123456789abcdefgh=",
      ].join("\n"),
    );
    expect(got.filter((g) => g.indexOf("crypt_hash=") === 0)).toHaveLength(1);
    expect(got.filter((g) => g.indexOf("argon2_hash=") === 0)).toHaveLength(1);
    expect(got.filter((g) => g.indexOf("framework_hash=") === 0)).toHaveLength(1);
  });

  it("finds a hash in a hash-named field", () => {
    expect(body(`{"password_hash":"5f4dcc3b5aa765d61d8327deb882cf99"}`)).toEqual([
      "field_hash=5f4dcc3b5aa765d61d8327deb882cf99",
    ]);
  });

  it("finds an NTLM pair and a shadow line", () => {
    const got = body("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\nroot:$6$xyz$aaaaaaaaaaaaaaaaaaaaaaaa:19000:0:99999:7:::");
    expect(got.filter((g) => g.indexOf("ntlm_pair=") === 0)).toHaveLength(1);
    expect(got.filter((g) => g.indexOf("shadow_line=") === 0)).toHaveLength(1);
  });

  it("leaves bare hex alone unless asked", () => {
    expect(body(`{"etag":"5f4dcc3b5aa765d61d8327deb882cf99"}`)).toEqual([]);
    expect(body(`{"etag":"5f4dcc3b5aa765d61d8327deb882cf99"}`, { hexHashes: true })).toEqual([
      "hex_hash=5f4dcc3b5aa765d61d8327deb882cf99",
    ]);
  });
});

describe("keys and tokens", () => {
  it("finds the formats that name their issuer", () => {
    const got = body(
      [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "a".repeat(36),
        "xoxb-1234567890-abcdef",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
        "glpat-" + "b".repeat(20),
        "sk-ant-api03-" + "c".repeat(40),
        "npm_" + "d".repeat(36),
        "shpat_" + "0123456789abcdef0123456789abcdef",
      ].join(" "),
    );
    expect(got).toContain("aws_access_key=AKIAIOSFODNN7EXAMPLE");
    expect(got).toContain("github_token=ghp_" + "a".repeat(36));
    expect(got).toContain("gitlab_token=glpat-" + "b".repeat(20));
    expect(got).toContain("anthropic_key=sk-ant-api03-" + "c".repeat(40));
    expect(got).toHaveLength(9);
  });

  it("finds a JWT wherever it is", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4ifQ.c2lnbmF0dXJl";
    expect(body(`{"token":"${jwt}"}`)).toContain("jwt=" + jwt);
    expect(found({ head: "GET / HTTP/1.1\r\nCookie: auth=" + jwt })).toContain("jwt=" + jwt);
  });

  it("finds a private key, however it is wrapped", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX\n-----END RSA PRIVATE KEY-----";
    expect(body("key: " + pem)).toEqual(["private_key=" + pem]);
    const json = `{"private_key":"-----BEGIN PRIVATE KEY-----\\nMIIBOgIBAAJBAKj3\\n-----END PRIVATE KEY-----\\n"}`;
    expect(body(json)[0].indexOf("private_key=-----BEGIN")).toBe(0);
  });

  it("finds credentials in a connection string", () => {
    const got = body(`{"database_url":"postgres://admin:s3cret@db.internal:5432/app"}`);
    expect(got).toContain("url_credentials=postgres://admin:s3cret@db.internal");
  });

  it("only flags generic keys that look random", () => {
    expect(body("api_key=aaaaaaaaaaaaaaaaaaaa")).toEqual([]);
    expect(body("api_key=Zx9Qm2Lw7Vb4Np8Kr3Ty")).toEqual(["field_api_key=Zx9Qm2Lw7Vb4Np8Kr3Ty"]);
  });

  it("finds a session cookie and an API key header", () => {
    const head = [
      "GET /app HTTP/1.1",
      "Cookie: theme=dark; PHPSESSID=8f2kq9d1x7bqw3zt5r6y; csrftoken=Zx9Qm2Lw7Vb4Np8Kr3Ty",
      "X-Api-Key: 4f8b2c9e1d7a6b3f5e0c",
    ].join("\r\n");
    const got = found({ head });
    expect(got).toContain("field_session=8f2kq9d1x7bqw3zt5r6y");
    expect(got).toContain("field_api_key=4f8b2c9e1d7a6b3f5e0c");
  });
});

describe("authorization headers", () => {
  it("decodes Basic credentials", () => {
    expect(found({ head: "GET / HTTP/1.1\r\nAuthorization: Basic " + btoa("admin:letmein") })).toEqual([
      "auth_header=admin:letmein",
    ]);
  });

  it("reads any scheme", () => {
    expect(found({ head: "GET / HTTP/1.1\r\nauthorization: bearer abc123def456ghi" })).toEqual(["auth_header=abc123def456ghi"]);
    expect(found({ head: "GET / HTTP/1.1\r\nAuthorization: Token 9f8e7d6c5b4a3210ffff" })).toEqual([
      "auth_header=9f8e7d6c5b4a3210ffff",
    ]);
    expect(found({ head: "POST / HTTP/1.1\r\nProxy-Authorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAA" })).toEqual([
      "auth_header=TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAA",
    ]);
  });

  it("reads a credential sent with no scheme at all", () => {
    expect(found({ head: "GET / HTTP/1.1\r\nAuthorization: 8f2kq9d1x7bqw3zt5r6y" })).toEqual([
      "auth_header_bare=8f2kq9d1x7bqw3zt5r6y",
    ]);
  });

  it("finds the AWS key in a SigV4 signature", () => {
    const head =
      "GET / HTTP/1.1\r\nAuthorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc";
    expect(found({ head })).toContain("aws_access_key=AKIAIOSFODNN7EXAMPLE");
  });
});

describe("personal and payment data", () => {
  it("finds card numbers that pass Luhn, and no others", () => {
    expect(body("card 4111 1111 1111 1111 here")).toEqual(["credit_card=4111 1111 1111 1111"]);
    expect(body("order 4111111111111112")).toEqual([]);
  });

  it("finds a card and its security code in a payment form", () => {
    const got = found({ body: "cardNumber=4012888888881881&cvv=737&exp=12%2F30" });
    expect(got).toContain("field_card=4012888888881881");
    expect(got).toContain("field_cvv=737");
  });

  it("finds a plausible SSN and rejects the impossible ones", () => {
    expect(body("ssn 234-56-7890")).toEqual(["ssn=234-56-7890"]);
    expect(body("code 000-12-3456 and 123-45-6789")).toEqual([]);
  });

  it("checks an IBAN's checksum", () => {
    expect(body("iban GB82 WEST 1234 5698 7654 32")).toEqual(["iban=GB82 WEST 1234 5698 7654 32"]);
    expect(body("iban GB82 WEST 1234 5698 7654 33")).toEqual([]);
  });

  it("finds a date of birth in a named field", () => {
    const got = body(`{"dob":"1981-04-02","nickname":"ace"}`);
    expect(got).toContain("field_dob=1981-04-02");
  });

  it("finds a government identifier in a named field", () => {
    expect(body(`{"passport_number":"X1234567"}`)).toEqual(["field_gov_id=X1234567"]);
  });
});

describe("settings", () => {
  it("runs only the detectors listed", () => {
    expect(body("AKIAIOSFODNN7EXAMPLE and ssn 234-56-7890", { detectors: ["ssn"] })).toEqual(["ssn=234-56-7890"]);
  });

  it("takes a whole category", () => {
    const got = body("AKIAIOSFODNN7EXAMPLE and ssn 234-56-7890", { detectors: ["secret-key"] });
    expect(got).toEqual(["aws_access_key=AKIAIOSFODNN7EXAMPLE"]);
  });

  it("skips what it is told to skip", () => {
    expect(body("AKIAIOSFODNN7EXAMPLE and ssn 234-56-7890", { skip: ["personal-data"] })).toEqual([
      "aws_access_key=AKIAIOSFODNN7EXAMPLE",
    ]);
    expect(body("AKIAIOSFODNN7EXAMPLE and ssn 234-56-7890", { skip: ["aws_access_key"] })).toEqual(["ssn=234-56-7890"]);
  });

  it("ignores the values it is told to ignore", () => {
    expect(body("AKIAIOSFODNN7EXAMPLE", { ignoreValues: ["akiaiosfodnn7example"] })).toEqual([]);
  });

  it("stops at the cap", () => {
    const many = ["AKIAIOSFODNN7EXAMPL1", "AKIAIOSFODNN7EXAMPL2", "AKIAIOSFODNN7EXAMPL3", "AKIAIOSFODNN7EXAMPL4"].join(" ");
    expect(body(many, { maxHits: 2 })).toHaveLength(2);
  });

  it("stops reading a body at the size cap", () => {
    expect(body("x".repeat(100) + " AKIAIOSFODNN7EXAMPLE", { maxBody: 50 })).toEqual([]);
  });
});

describe("the catalog", () => {
  it("has a unique id for every detector", () => {
    const ids: Record<string, boolean> = {};
    for (const d of CATALOG) {
      expect(ids[d.id]).toBeUndefined();
      ids[d.id] = true;
    }
    expect(CATALOG.length).toBeGreaterThan(40);
  });
});
