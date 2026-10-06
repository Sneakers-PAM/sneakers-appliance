# Error codes

Every coded error carries a number and a stable symbol. The kit prints `SYMBOL (code): sentence`;
on the box the console and init's log show the same. 1xxx are the kit and the verification chain it
shares with `Image.Stage`; 2xxx are boot.

| Code | Symbol | Meaning |
|---|---|---|
| 1001 | `KIT_PIN_MISSING` | this kit was built without one of its pins, or with a channel other than production or lab |
| 1002 | `KIT_SIG_MISSING` | the artifact or `release.yaml` has no signature |
| 1003 | `KIT_WRONG_SIGNER` | signed, but not by the pinned key |
| 1004 | `KIT_CHANNEL` | the manifest's channel isn't the kit's |
| 1005 | `KIT_KIT_TOO_OLD` | `kitMin` is above this kit's version |
| 1006 | `KIT_DIGEST_MISMATCH` | a layer's SHA-256 differs from `appliance.yaml` |
| 1007 | `KIT_AUTHENTICODE` | the UKI or loader doesn't verify against the pinned db certificate |
| 1008 | `KIT_VERITY_MISMATCH` | the root image doesn't match the UKI's root hash |
| 1009 | `KIT_BUNDLE_MISMATCH` | the bundle and `release.yaml` differ, or k0s isn't the pinned binary |
| 1010 | `KIT_IMAGE_UNSIGNED` | a bundled image lacks a valid org signature |
| 1011 | `KIT_TOOL_MISSING` | a tool the format needs isn't available |
| 1012 | `KIT_MANIFEST_INVALID` | `appliance.yaml` doesn't parse or breaks a structural rule |
| 1013 | `KIT_SOURCE_UNREADABLE` | the artifact can't be resolved or read |
| 2001 | `ROOT_NOT_FOUND` | no root slot matches the signed root hash, and no install medium holds the root image |
