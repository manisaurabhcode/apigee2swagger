Low-level mapping matrix between Apigee policies and their IBM API Connect equivalents, including configuration mappings at the attribute level.

Below is a comprehensive policy-by-policy mapping table. It is divided by policy families (Security, Traffic, Mediation, Caching, Transform, Scripting, Logging, etc.) and includes:
	•	Apigee Policy Type / Function
	•	IBM API Connect Equivalent Policy
	•	Mapping Details / Config Translation
	•	Migration Notes / Gaps

This table is meant to guide both your automated mappings (Step 2) and manual review for edge cases.

⸻

🧩 APIGEE → IBM API CONNECT POLICY MAPPING MATRIX

Apigee Policy Type	IBM API Connect Equivalent	Configuration Mapping (Low-Level)	Migration Notes / Gaps
VerifyAPIKey	validate-api-key (or security scheme client-id)	APIKey → in (e.g. request.header.apikey)ContinueOnError → optional failAction<DisplayName> → title	IBM API Connect typically defines client-id enforcement via x-ibm-configuration.securityDefinitions. Assembly mapping approximates runtime validation.
OAuthV2	validate-jwt / oauth-validate	Operation → grantType (e.g., VerifyAccessToken → “validate”)TokenStore → settings.tokenStoreAccessToken → part of inputToken config	Apigee OAuthV2 has multiple modes (generate/verify). IBM splits token generation and validation across different flows.
VerifyJWT	validate-jwt	<Issuer> → issuer<Audience> → audience<JWKSUri> → jwksUri<Algorithm> → algorithm	Direct translation; both platforms support similar JWT validation parameters.
GenerateJWT	generate-jwt	<Algorithm> → algorithm<Claims> → claims (JSON)<Subject> / <Issuer> → same fields	IBM supports JWT generation in assembly; mapping is straightforward.
SpikeArrest	rate-limit	<Rate> → rate.value (e.g. 10ps → 10 per second)<Identifier> → key field if available	IBM’s rate-limit syntax expects explicit value and unit. Apigee uses “10ps”, “100pm”.
Quota	quota	<Interval> → interval (minutes/seconds)<Allow> → limit<Identifier> → key	IBM quota supports similar controls; Apigee uses static/shared counters per API/Client.
ConcurrentRateLimit	concurrent-rate-limit	<Concurrency> → limit<Identifier> → key	IBM supports concurrency limits but needs external counters.
AssignMessage	set-variable	<Set> elements → key-value pairs in actions array<AssignTo> target → context (response/request)<Payload> → body content	Apigee’s AssignMessage merges multiple contexts; IBM’s set-variable sets headers/body/params individually.
ExtractVariables	parse or extract-variables	<JSONPath> / <XPath> → parse.jsonPath / parse.xpath<Variable> → destination variable name	IBM supports variable extraction through GatewayScript or assembly parse policy.
RaiseFault	raise-fault	<FaultResponse.StatusCode> → status<ReasonPhrase> → reason<Message> → message	Direct mapping. IBM’s raise-fault has similar constructs.
ServiceCallout	invoke	<Request> target → target-url<Request> headers/body → input mapping<Response> variable → output context	IBM’s invoke policy calls another URL. If the ServiceCallout targets a named TargetEndpoint, replace with full backend URL.
MessageLogging	log	<LogLevel> → level<Message> → message<LogEndpoint> → destination	IBM supports “log” policy for Gateway logging or DataPower logging. Apigee supports multiple destinations (syslog, cloud logging).
ResponseCache	cache-response	<CacheResource> → cache<ExpirySettings.TimeoutInSec> → timeout<CacheKey> → key-expression	Direct caching concept. IBM uses TTL-based caching; behavior similar.
PopulateCache	cache-put	<CacheResource> → cache<ExpirySettings> → TTL	IBM cache-put allows manual population of a cache entry.
InvalidateCache	cache-delete	<CacheResource> → cache<Keys> → key pattern	IBM cache-delete removes cached entry; equivalent semantics.
XMLToJSON	map / transform (xml-to-json)	<Format> → "xml-to-json"	Both support XML/JSON transformations.
JSONToXML	map / transform (json-to-xml)	<Format> → "json-to-xml"	Straightforward conversion.
Javascript	javascript	<ResourceURL> / inline code → script field	IBM supports JavaScript in assembly; uses GatewayScript runtime (Node.js).
JavaCallout	java-callout	<Class> → class<ResourceURL> → reference to JAR<Properties> → parameters	Requires Java extension to be installed on IBM Gateway.
PythonScript	python	<Source> or inline code → script	IBM supports limited scripting in some versions; otherwise treat as custom.
StatisticsCollector	collect-metrics	<Statistics> elements → metrics configuration	IBM metrics collection handled differently; replicate using Gateway analytics or log policy.
RaiseFault (custom messages)	raise-fault	<FaultRules> → conditional faults<MessageTemplate> → body of fault	Needs manual migration if conditions complex.
KeyValueMapOperations (KVM)	set-variable or key-value-store (custom)	<Get> / <Put> / <Delete> → variable read/write	IBM supports property map or assembly variables; may require script.
SharedFlowCallout	invoke (shared flow)	<SharedFlowBundleName> → invoke.target = shared assembly reference	IBM requires explicit call to another API/assembly; manual mapping.
StatisticsCollector	collect-metrics	<Statistics> → metric key-value pairs	Often replaced by IBM analytics integration.
RaiseFault (Complex)	raise-fault	<Condition> → attach conditional execution	IBM supports condition expressions per policy.
AssignMessage (Create new message)	set-variable + set-body	<AssignTo> = new message target<Payload> = new body<Set> = headers	IBM separate set-variable and set-body policies.
SharedFlowParameter (Config)	set-variable (predefined)	<Parameter> → variable assignment	IBM doesn’t have direct shared flow parameters.
AccessControl	validate-api-key or invoke (auth)	<App> / <Resource> → check scopes	May require IBM “security-definition” conversion.
XMLThreatProtection	validate (schema validation)	<Element> limits → schema constraints	IBM supports XML/JSON validation policy.
JSONThreatProtection	validate (JSON schema)	<MaxElementDepth> / <MaxArrayElements> → validation constraints	IBM “validate” policy can enforce JSON constraints.
VerifyAPIKey (Conditional)	conditional invoke or validate	<Condition> → if: expression	IBM supports “condition” wrapper per assembly action.
ConcurrentRateLimit	rate-limit (concurrent)	<MaxConcurrentRequests> → concurrency	IBM supports concurrency control with DataPower-based limiters.
RaiseFault (with template)	raise-fault	<MessageTemplate> → response body	IBM supports custom fault body.


⸻

🔍 Notes on Mapping Depth

Category	Mapping Coverage	Comments
Security (VerifyAPIKey, OAuthV2, JWT)	1:1 or near	IBM’s security definitions align well; only token issuance differs.
Traffic Mgmt (SpikeArrest, Quota, Concurrency)	1:1 or near	IBM supports rate/quota directly; concurrency may need DataPower config.
Message Mediation (AssignMessage, ExtractVariables, RaiseFault)	1:1	Straightforward translation; both support variables, headers, conditions.
Caching (ResponseCache, PopulateCache, InvalidateCache)	1:1	IBM caching config similar to Apigee.
Transform (XML↔JSON, ThreatProtection)	1:1	IBM “validate” and “transform” policies cover both.
Scripting (JS, Java, Python)	partial	IBM supports GatewayScript/Java; Python limited.
Logging / Analytics	partial	IBM log supports similar output; analytics mapping manual.
Shared Flows / Reusable logic	custom	IBM equivalent is assembly or invoke other APIs; must refactor.
KVM / DataStore	partial	IBM lacks direct KVM; use variables, DataPower, or external store.


⸻

🧠 Mapping Example (Visual Breakdown)

Let’s illustrate one example in a side-by-side low-level configuration mapping:

Apigee XML	IBM API Connect JSON
xml<br><SpikeArrest name="RateLimit10ps"><Rate>10ps</Rate><Identifier>request.header.userid</Identifier></SpikeArrest>	json<br>{ "rate-limit": { "title": "RateLimit10ps", "rate": { "value": 10, "unit": "second" }, "key": "request.header.userid" } }
xml<br><VerifyAPIKey name="AuthKey"><APIKey ref="request.header.apikey"/></VerifyAPIKey>	json<br>{ "validate-api-key": { "title": "AuthKey", "in": "request.header.apikey" } }
xml<br><AssignMessage name="AddHeader"><Set><Headers><Header name="X-Version">1.0</Header></Headers></Set></AssignMessage>	json<br>{ "set-variable": { "title": "AddHeader", "actions": [ { "set": "response.header.X-Version", "value": "1.0" } ] } }


⸻

🧩 Key Migration Gaps (Require Manual Attention)

Category	Details
OAuth Token Generation (Apigee OAuthV2 GenerateAccessToken)	IBM doesn’t provide a policy for issuing OAuth tokens directly — must be replaced by IBM’s native OAuth provider or custom microservice.
KeyValueMapOperations (KVM)	IBM has no direct KVM; replace with Gateway variables or external data sources.
Custom Java / Python Policies	Must manually repackage into IBM DataPower extension or GatewayScript.
SharedFlows	Must refactor as separate IBM assemblies or reusable subflows.
Analytics / StatsCollector	IBM API Connect integrates via DataPower analytics — cannot migrate inline.
Conditional Flows	Conditions can be mapped to assembly-level “if:” expressions, but need manual review.


⸻

Would you like me to now generate a machine-readable JSON/YAML mapping reference file from this table (so your Step 2 script can consume it dynamically rather than hardcoding each policy mapping)?
That would make your migration engine data-driven and easier to extend.