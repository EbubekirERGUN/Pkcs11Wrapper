# 2026-04 final admin showcase set

This folder contains the **final committed README showcase slice** for the admin panel.

It intentionally keeps the gallery small:

1. `admin-dashboard.png` — top-level operations dashboard hero
2. `admin-devices.png` — device profile inventory + governance surface
3. `admin-slots.png` — slot/token visibility surface

## Why this replaces the earlier preview concept

The earlier preview branch (`showcase-2026-04-ui-preview`, PR #63 concept) proved that screenshots were worth adding, but it was still preview-grade: more exploratory, less intentional, and not yet wired cleanly into the main README.

This folder is the final replacement path:

- smaller set
- stable filenames
- directly referenced from `README.md` / `README.tr.md`
- captured from the current admin panel on this branch instead of keeping a second preview-only showcase track alive

## Capture recipe used for these images

The committed PNGs were generated from the current branch with:

```bash
./eng/capture-admin-showcase.sh
```

That script:

- creates a temporary SoftHSM fixture via `eng/setup-softhsm-fixture.sh`
- builds the admin web app + existing Playwright runtime dependency from `tests/Pkcs11Wrapper.Admin.E2E`
- seeds a temporary admin storage root with a real SoftHSM-backed device profile
- runs a headless Playwright capture flow against the live admin panel
- writes fresh screenshots under `artifacts/showcase/admin/showcase/`

## Validation notes

- The screenshots were generated from a live local admin runtime, not mocked HTML.
- Device/slot values come from the seeded SoftHSM fixture used by the repo's admin validation path.
- The dashboard image is intentionally cropped to the designed hero slice so the README highlights the public-facing surface instead of transient lower-page runtime noise.
- The README integration should be checked by rendering `README.md` on GitHub or any CommonMark viewer that supports inline HTML images.
