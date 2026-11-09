# Security policy

## Supported versions

Only the latest release receives security fixes while the project is below
version 1.0.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem, and never
include real secrets or personal data in a report.

Report it privately through GitHub: go to the repository's **Security** tab
and choose **Report a vulnerability**. Include the version, a synthetic input
that reproduces the problem, and the impact you expect.

You should get an acknowledgement within 7 days. Once the problem is
confirmed, a fix and an advisory will be published, and you will be credited
unless you prefer not to be.

## What counts as a vulnerability

logredact's job is to stop sensitive data from leaking, so these are treated
as security issues:

- input for which a value a built-in detector is documented to catch
  survives redaction (a **leak**);
- output that reveals information about a redacted value, other than what the
  pseudonym scheme is documented to reveal;
- `--check` output that includes a sensitive value;
- a pattern with catastrophic backtracking that lets crafted input hang the
  tool;
- crashes on any input that cause it to write partial output without an error.

Data that logredact is documented **not** to detect (see Limitations in the
README) is a feature request, not a vulnerability.

## Handling of keys

The pseudonym key is read only from an environment variable, is never
written anywhere, and is never printed. logredact makes no network requests.
