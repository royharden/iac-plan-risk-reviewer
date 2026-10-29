# Numbered API-informed amendment r2

D12-origin-backend-API-r1 and API-addendum-r2 were read after initial control
freeze and before successor code inspection. Public injection is
LocalMetadataBackend(observations=dependency), where dependency implements
lstat/readlink/open_read/fstat. All four are required; invalid injection refuses
without any calls or fallback. Tests exercise that same backend logic, never
private _stat overrides, real OS adapter calls or operational objects.

Retain the API's finite process facts rather than inventing launcher syntax.
observe_owned uses the caller-bound six-key Protocol relation and exact frozen
slot. Link facts returned from injected Metadata remain modeled DATA; even an
actual_link_verified field is not physical evidence in these tests.
