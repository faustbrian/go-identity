# Changelog

## Unreleased

- Add the explicit hCaptcha Siteverify Publisher/Pro profile with optional
  deprecated credit and native error-code availability. Action/score/origin and
  undocumented returned-sitekey proof stay unavailable; prior profiles remain.

- Add explicit reCAPTCHA classic Siteverify v3/standard evidence with score
  availability, native error-code availability and two-minute challenge bounds.
  Scores remain facts for risk-owned policy; Turnstile v0/free is unchanged.

- Add stateless bounded CAPTCHA provider verification and the exact callback for
  the risk-owned issuer, preserving original command/flow custody and private
  typed native evidence without creating replay, policy or durability authority.
  The first selected profile is Turnstile Siteverify v0/free; canonical security
  events and complete module qualification remain pending.
