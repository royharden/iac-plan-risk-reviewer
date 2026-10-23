# Terraform evidence resolver

M4 implements its own RFC6901 resolver in `iac_review.evidence`. There is no S5
runtime dependency, copied implementation, native Terraform adapter claim, or
upstream schema compatibility claim. A future bridge requires an explicit wire
extension and consumer validation.

References bind the raw SHA256, raw resource index, `(address, deposed)` identity,
opaque resource key, side, pointer, expected tagged state and decision/supporting
role. Resolution reopens the original regular local file, verifies its digest and
resource identity, decodes exact pointer escapes and reapplies ancestor masks.
Missing facts resolve only when the immediate parent exists and its final token
is absent. Unknown and sensitive ancestors dominate child values.

An object-root `known({})` is a structural object-existence summary, not an assertion
that the source object is empty. It supports R4 prior existence without exporting
arbitrary attributes. Nested objects never become general-purpose fact values.
Primitive lists are available only without descendant unknown/sensitive markers.
Private reports may contain exact addresses/pointers and are sensitive artifacts;
marked values must stay masked, while shareable reports exclude these locators.

Dirty Mode status: construction only. Resolver pointer/mask/mutation, producer
compatibility, effect and privacy tests have not run. Source-byte/read bounds and
monotonic checkpoints are implemented, but the 30-second limit is cooperative;
hard preemption and large-plan traversal/memory measurements remain deferred.
