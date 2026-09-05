package collect

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func bundleFrom(t *testing.T, planJSON string) *Bundle {
	t.Helper()
	bundle, err := FromPlanJSON(strings.NewReader(planJSON))
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

// findReference returns the single reference matching source/ref/via,
// failing if there is not exactly one.
//
// References are unresolved: source and rawRef are the addresses the
// configuration writes, without count subscripts. Pairing them to concrete
// and is tested there.
func findReference(t *testing.T, bundle *Bundle, source, ref, via string) Reference {
	t.Helper()
	var found []Reference
	for _, reference := range bundle.References {
		if reference.Source == source && reference.Ref == ref && reference.Via == via {
			found = append(found, reference)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s -%s-> %s, got %d: %+v", source, via, ref, len(found), bundle.References)
	}
	return found[0]
}

func TestCollectDeniedKeySpellings(t *testing.T) {
	patterns := []string{
		"password", "passwd", "secret", "token", "api_key", "private_key",
		"access_key", "client_secret", "authorization", "cookie", "user_data",
		"connection_string", "certificate_body", "secret_string",
	}
	for _, pattern := range patterns {
		words := strings.Split(pattern, "_")
		camel := words[0]
		pascal := ""
		for index, word := range words {
			title := strings.ToUpper(word[:1]) + word[1:]
			pascal += title
			if index > 0 {
				camel += title
			}
		}
		for _, key := range []string{
			pattern, strings.ToUpper(pattern), strings.ReplaceAll(pattern, "_", "-"),
			strings.ReplaceAll(pattern, "_", "."), strings.ReplaceAll(pattern, "_", ""),
			strings.ToUpper(strings.ReplaceAll(pattern, "_", "")), camel, pascal,
			"DB_" + strings.ToUpper(pattern), "db" + pascal, pascal + "ARN",
			"db_" + pattern + "_value",
			"/service/" + pascal, "db:" + pascal, "db " + pascal, "\u00e9" + pascal,
		} {
			t.Run(key, func(t *testing.T) {
				assertCollectedKey(t, key, true)
			})
		}
	}
	for _, tc := range []struct {
		key    string
		denied bool
	}{
		{"APIKey", true}, {"apiKEY", true}, {"dbAPIKey", true},
		{"API_TOKEN", true}, {"OAuthToken", true}, {"DBPassword", true},
		{"DB.PASSWORD", true}, {"DB-API-KEY", true}, {"db2Password", true},
		{"/service/Password", true}, {"db:Token", true}, {"db Password", true}, {"\u00e9Secret", true},
		{"/service/APIKey", true}, {"db:API_KEY", true}, {"\u00e9PASSWORD", true},
		{"Name", false}, {"CIDR", false}, {"vpcID", false}, {"APIEndpoint", false},
		{"monkey", false}, {"tokenizer", false}, {"passwordless", false},
		{"secretary", false}, {"key_pair", false}, {"", false},
	} {
		t.Run(tc.key, func(t *testing.T) {
			assertCollectedKey(t, tc.key, tc.denied)
		})
	}
}

func assertCollectedKey(t *testing.T, key string, denied bool) {
	t.Helper()
	// Exercise nested maps and lists through the actual plan-to-bundle path,
	// without a sensitivity mask. Check detection separately from sanitization.
	input := map[string]any{
		"blocks": []any{map[string]any{key: "sentinel-value"}},
		"cidr":   "10.0.0.0/16",
	}
	if got := ContainsDeniedKey(input); got != denied {
		t.Errorf("ContainsDeniedKey for %q = %v, want %v", key, got, denied)
	}
	values, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	bundle := bundleFrom(t, fmt.Sprintf(`{"format_version":"1.2","resource_changes":[{
		"address":"test.main","change":{"after":%s,"after_sensitive":{}}
	}]}`, values))
	clean := bundle.Resources[0].Values
	if ContainsDeniedKey(clean) {
		t.Errorf("sanitized values still contain a denied key: %+v", clean)
	}
	block := clean["blocks"].([]any)[0].(map[string]any)
	value, exists := block[key]
	if exists == denied || exists && value != "sentinel-value" {
		t.Fatalf("key %q: value=%v exists=%v, denied=%v", key, value, exists, denied)
	}
	wantRemoved := 0
	if denied {
		wantRemoved = 1
	}
	if bundle.Stats.DeniedKeysRemoved != wantRemoved || clean["cidr"] != "10.0.0.0/16" {
		t.Fatalf("unexpected sanitization: %+v", bundle)
	}
}

func TestCollectRemovesSensitiveAndCredentialFields(t *testing.T) {
	bundle := bundleFrom(t, `{
  "format_version":"1.2","terraform_version":"1.9.0",
  "resource_changes":[{
    "address":"aws_db_instance.main","mode":"managed","type":"aws_db_instance","name":"main","provider_name":"registry.terraform.io/hashicorp/aws",
    "change":{"actions":["create"],"after":{"address":"db.internal","port":5432,"password":"visible-password","nested":{"apiToken":"visible-token","cidr":"10.0.0.0/16"},"tags":{"Name":"database"}},"after_sensitive":{"password":true}}
  },{
    "address":"aws_db_subnet_group.main","mode":"managed","type":"aws_db_subnet_group","name":"main",
    "change":{"actions":["create"],"after":{"name":"private"},"after_sensitive":{}}
  }],
  "configuration":{"root_module":{"resources":[{"address":"aws_db_instance.main","expressions":{"subnet_group":{"references":["aws_db_subnet_group.main.id"]}}}]}}
}`)

	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, secret := range []string{"visible-password", "visible-token", `"password"`, `"apiToken"`} {
		if strings.Contains(text, secret) {
			t.Fatalf("bundle leaked %q: %s", secret, text)
		}
	}
	for _, topology := range []string{"db.internal", "5432", "10.0.0.0/16", "database", "aws_db_subnet_group.main"} {
		if !strings.Contains(text, topology) {
			t.Fatalf("bundle removed topology %q: %s", topology, text)
		}
	}
	if bundle.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %d, want %d", bundle.SchemaVersion, SchemaVersion)
	}
}

// A top-level attribute reference must be marked as such, because a consumer that
// resolves containment refuses to match a reference claiming to sit inside a block.
func TestTopLevelReferenceHasNoBlock(t *testing.T) {
	bundle := bundleFrom(t, `{
  "format_version":"1.2",
  "resource_changes":[
    {"address":"aws_subnet.public","type":"aws_subnet","name":"public","change":{"actions":["create"],"after":{}}},
    {"address":"aws_vpc.main","type":"aws_vpc","name":"main","change":{"actions":["create"],"after":{}}}
  ],
  "configuration":{"root_module":{"resources":[
    {"address":"aws_subnet.public","expressions":{"vpc_id":{"references":["aws_vpc.main.id","aws_vpc.main"]}}}
  ]}}
}`)

	reference := findReference(t, bundle, "aws_subnet.public", "aws_vpc.main", "vpc_id")
	if reference.BlockType != "" {
		t.Errorf("block_type = %q, want empty", reference.BlockType)
	}
	if reference.BlockIndex != -1 {
		t.Errorf("block_index = %d, want -1", reference.BlockIndex)
	}
	// Terraform reports the same reference twice; only the more specific spelling
	// should survive, as one edge rather than two.
	if reference.Ref != "aws_vpc.main" {
		t.Errorf("raw_ref = %q, want aws_vpc.main", reference.Ref)
	}
}

// This is the case bundle-v1 could not express. Each route block pairs a gateway
// with a destination CIDR, and only the block ordinal reunites them downstream.
func TestNestedRouteBlocksCarryTypeAndIndex(t *testing.T) {
	bundle := bundleFrom(t, `{
  "format_version":"1.2",
  "resource_changes":[
    {"address":"aws_route_table.public","type":"aws_route_table","name":"public","change":{"actions":["create"],"after":{"route":[{"cidr_block":"0.0.0.0/0"},{"cidr_block":"10.1.0.0/16"}]}}},
    {"address":"aws_internet_gateway.main","type":"aws_internet_gateway","name":"main","change":{"actions":["create"],"after":{}}},
    {"address":"aws_vpc_peering_connection.peer","type":"aws_vpc_peering_connection","name":"peer","change":{"actions":["create"],"after":{}}}
  ],
  "configuration":{"root_module":{"resources":[
    {"address":"aws_route_table.public","expressions":{"route":[
      {"cidr_block":{"constant_value":"0.0.0.0/0"},"gateway_id":{"references":["aws_internet_gateway.main.id"]}},
      {"cidr_block":{"constant_value":"10.1.0.0/16"},"vpc_peering_connection_id":{"references":["aws_vpc_peering_connection.peer.id"]}}
    ]}}
  ]}}
}`)

	gateway := findReference(t, bundle, "aws_route_table.public", "aws_internet_gateway.main", "gateway_id")
	if gateway.BlockType != "route" || gateway.BlockIndex != 0 {
		t.Errorf("gateway route: block_type=%q block_index=%d, want route/0", gateway.BlockType, gateway.BlockIndex)
	}

	peering := findReference(t, bundle, "aws_route_table.public", "aws_vpc_peering_connection.peer", "vpc_peering_connection_id")
	if peering.BlockType != "route" || peering.BlockIndex != 1 {
		t.Errorf("peering route: block_type=%q block_index=%d, want route/1", peering.BlockType, peering.BlockIndex)
	}
}

// A single (non-repeating) nested block still reports the inner attribute name,
// so that "vpc_config { subnet_ids = ... }" is not flattened to via "vpc_config".
func TestSingleNestedBlockReportsInnerAttribute(t *testing.T) {
	bundle := bundleFrom(t, `{
  "format_version":"1.2",
  "resource_changes":[
    {"address":"aws_eks_cluster.main","type":"aws_eks_cluster","name":"main","change":{"actions":["create"],"after":{}}},
    {"address":"aws_subnet.private","type":"aws_subnet","name":"private","change":{"actions":["create"],"after":{}}}
  ],
  "configuration":{"root_module":{"resources":[
    {"address":"aws_eks_cluster.main","expressions":{"vpc_config":{"subnet_ids":{"references":["aws_subnet.private.id"]}}}}
  ]}}
}`)

	reference := findReference(t, bundle, "aws_eks_cluster.main", "aws_subnet.private", "subnet_ids")
	if reference.BlockType != "vpc_config" || reference.BlockIndex != 0 {
		t.Errorf("block_type=%q block_index=%d, want vpc_config/0", reference.BlockType, reference.BlockIndex)
	}
}

// Inside a module body Terraform writes addresses relative to that module, while
// resource_changes addresses them absolutely. Without the module prefix these
// edges resolve to nothing and vanish.
func TestModuleRelationshipsAreQualified(t *testing.T) {
	bundle := bundleFrom(t, `{
  "format_version":"1.2",
  "resource_changes":[
    {"address":"module.network.aws_subnet.public","module_address":"module.network","type":"aws_subnet","name":"public","change":{"actions":["create"],"after":{}}},
    {"address":"module.network.aws_vpc.main","module_address":"module.network","type":"aws_vpc","name":"main","change":{"actions":["create"],"after":{}}}
  ],
  "configuration":{"root_module":{"resources":[],"module_calls":{"network":{"module":{"resources":[
    {"address":"aws_subnet.public","expressions":{"vpc_id":{"references":["aws_vpc.main.id"]}}}
  ]}}}}}
}`)

	reference := findReference(t, bundle, "module.network.aws_subnet.public", "module.network.aws_vpc.main", "vpc_id")
	if reference.BlockIndex != -1 {
		t.Errorf("block_index = %d, want -1", reference.BlockIndex)
	}
}

// A redacted object inside a list must hold its position. Consumers index nested
// blocks positionally, so collapsing or nulling an element silently renumbers
// every block after it.
func TestRedactedObjectArrayElementKeepsPosition(t *testing.T) {
	bundle := bundleFrom(t, `{
  "format_version":"1.2",
  "resource_changes":[{
    "address":"aws_security_group.main","type":"aws_security_group","name":"main",
    "change":{"actions":["create"],
      "after":{"ingress":[{"from_port":22},{"from_port":443}]},
      "after_sensitive":{"ingress":[true,false]}}
  }],
  "configuration":{"root_module":{"resources":[]}}
}`)

	ingress, ok := bundle.Resources[0].Values["ingress"].([]any)
	if !ok {
		t.Fatalf("ingress missing: %+v", bundle.Resources[0].Values)
	}
	if len(ingress) != 2 {
		t.Fatalf("ingress length = %d, want 2", len(ingress))
	}
	redacted, ok := ingress[0].(map[string]any)
	if !ok {
		t.Fatalf("redacted element is %T, want an empty object", ingress[0])
	}
	if len(redacted) != 0 {
		t.Errorf("redacted element = %v, want empty", redacted)
	}
	survivor, ok := ingress[1].(map[string]any)
	if !ok || survivor["from_port"] == nil {
		t.Errorf("element 1 lost its position: %+v", ingress[1])
	}
}

func TestResourceAddress(t *testing.T) {
	cases := map[string]string{
		"aws_vpc.main.id":                       "aws_vpc.main",
		"aws_vpc.main":                          "aws_vpc.main",
		"module.network.aws_vpc.main.id":        "module.network.aws_vpc.main",
		"module.a.module.b.aws_vpc.main.id":     "module.a.module.b.aws_vpc.main",
		"var.region":                            "var.region",
		"data.aws_ami.recent.id":                "data.aws_ami.recent",
		"data.aws_ami.recent":                   "data.aws_ami.recent",
		"module.network.data.aws_ami.recent.id": "module.network.data.aws_ami.recent",
		"data.foo":                              "",
		"single":                                "",
	}
	for input, expected := range cases {
		if actual := resourceAddress(input); actual != expected {
			t.Errorf("%s: got %q, want %q", input, actual, expected)
		}
	}
}

// Identical input must produce identical bytes: the receiver dedupes on a hash of
// this payload, and reuses a previous render when the hash matches.
func TestCollectIsDeterministic(t *testing.T) {
	plan := `{
  "format_version":"1.2",
  "resource_changes":[
    {"address":"aws_route_table.public","type":"aws_route_table","name":"public","change":{"actions":["create"],"after":{"tags":{"a":"1","b":"2","c":"3"}}}},
    {"address":"aws_internet_gateway.main","type":"aws_internet_gateway","name":"main","change":{"actions":["create"],"after":{}}},
    {"address":"aws_vpc.main","type":"aws_vpc","name":"main","change":{"actions":["create"],"after":{}}}
  ],
  "configuration":{"root_module":{"resources":[
    {"address":"aws_route_table.public","expressions":{
      "vpc_id":{"references":["aws_vpc.main.id"]},
      "route":[{"gateway_id":{"references":["aws_internet_gateway.main.id"]}}]
    }}
  ]}}
}`
	first, err := json.Marshal(bundleFrom(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	// Go randomizes map iteration per range, so repeating in-process is what
	// surfaces an ordering leak.
	for i := 0; i < 8; i++ {
		next, err := json.Marshal(bundleFrom(t, plan))
		if err != nil {
			t.Fatal(err)
		}
		if string(next) != string(first) {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, next)
		}
	}
}

// Instance pairing is no longer tested here.
//
// A version 3 bundle reports references unresolved, so which instance of a
// counted resource a reference means is the renderer's decision. Those cases
// live with the code that makes them, in internal/bundle of the renderer.
