## What this changes

<!-- One paragraph. What behaviour is different after this is merged? -->

## Why

<!-- The problem being solved. Link an issue if one exists. -->

## How it was verified

<!-- Delete what does not apply. -->

- [ ] `make check` passes (fmt, vet, unit tests with `-race`)
- [ ] `make test-integration` passes (needs root: real eBPF, real acquisition)
- [ ] `make demo` still completes, including the tamper-detection step
- [ ] New behaviour has a test that fails without the change

## Evidence-format impact

<!-- Anything that changes what lands in a bundle deserves a sentence here. -->

- [ ] No change to bundle layout, receipt fields or CASE/UCO output
- [ ] Bundle format changed, and `verify` still reads bundles written before it

## Checklist

- [ ] No credentials, keys, memory dumps or personal data added to the tree
- [ ] Documentation updated where behaviour changed
- [ ] Limitations documented honestly rather than omitted
