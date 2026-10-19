import { describe, it, expect } from "reproxy/testing";
import { classify, norm } from "../src/fields";

describe("norm", () => {
  it("puts a name in one form", () => {
    expect(norm("newPassword")).toBe("new_password");
    expect(norm("user[password]")).toBe("user_password");
    expect(norm("X-Api-Key")).toBe("x_api_key");
    expect(norm("data.attributes.pwd")).toBe("data_attributes_pwd");
  });
});

describe("classify", () => {
  const got = (name: string, value: string, minEntropy = 3.5) => {
    const f = classify(name, value, minEntropy);
    return f ? `${f.id}:${f.type}:${f.value}` : null;
  };

  it("reads a name's meaning", () => {
    expect(got("password", "hunter2")).toBe("field_password:credential:hunter2");
    expect(got("passwordHash", "5f4dcc3b5aa765d61d8327deb882cf99")).toBe("field_hash:hash:5f4dcc3b5aa765d61d8327deb882cf99");
    expect(got("sessionId", "8f2kq9d1x7bqw3zt5r6y")).toBe("field_session:token:8f2kq9d1x7bqw3zt5r6y");
    expect(got("cvv", "737")).toBe("field_cvv:payment-data:737");
    expect(got("iban", "GB82WEST12345698765432")).toBe("field_bank:payment-data:GB82WEST12345698765432");
    expect(got("dob", "1981-04-02")).toBe("field_dob:personal-data:1981-04-02");
  });

  it("records a password stored as its hash as a hash", () => {
    expect(got("password", "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")).toBe(
      "field_hash:hash:$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
    );
  });

  it("decodes a form-encoded value", () => {
    expect(got("newPassword", "s3cr3t%21")).toBe("field_password:credential:s3cr3t!");
  });

  it("turns down names that only talk about the thing", () => {
    for (const name of ["passwordStrength", "hasPassword", "password_required", "login_count", "card_type", "user_agent", "sec-fetch-user", "authorization", "is_secret", "num_tokens"]) {
      expect(got(name, "something")).toBeNull();
    }
  });

  it("turns down values that don't fit the name", () => {
    expect(got("cardNumber", "4111111111111112")).toBeNull(); // fails Luhn
    expect(got("cvv", "73")).toBeNull();
    expect(got("dob", "nope")).toBeNull();
    expect(got("api_key", "aaaaaaaaaaaaaaaaaaaa")).toBeNull(); // no entropy
    expect(got("username", "1234")).toBeNull(); // an id, not a name
  });

  it("reads a hash field holding something that isn't a hash as a password", () => {
    expect(got("passwordHash", "hunter2")).toBe("field_password:credential:hunter2");
  });

  it("takes the entropy floor from the settings", () => {
    expect(got("api_key", "aaaaaaaaaaaaaaaaaaaa", 0)).toBe("field_api_key:secret-key:aaaaaaaaaaaaaaaaaaaa");
  });
});
