package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCollectRemovesSensitiveAndCredentialFields(t *testing.T) {
	input := `{
  "format_version":"1.2","terraform_version":"1.9.0",
  "resource_changes":[{
    "address":"aws_db_instance.main","mode":"managed","type":"aws_db_instance","name":"main","provider_name":"registry.terraform.io/hashicorp/aws",
    "change":{"actions":["create"],"after":{"address":"db.internal","port":5432,"password":"visible-password","nested":{"apiToken":"visible-token","cidr":"10.0.0.0/16"},"tags":{"Name":"database"}},"after_sensitive":{"password":true}}
  },{
    "address":"aws_db_subnet_group.main","mode":"managed","type":"aws_db_subnet_group","name":"main",
    "change":{"actions":["create"],"after":{"name":"private"},"after_sensitive":{}}
  }],
  "configuration":{"root_module":{"resources":[{"address":"aws_db_instance.main","expressions":{"subnet_group":{"references":["aws_db_subnet_group.main.id"]}}}]}}
}`
	var plan rawPlan
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	if err := decoder.Decode(&plan); err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(collect(plan))
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
}

func TestResourceAddress(t *testing.T) {
	cases := map[string]string{
		"aws_vpc.main.id":                "aws_vpc.main",
		"module.network.aws_vpc.main.id": "module.network.aws_vpc.main",
		"var.region":                     "var.region",
	}
	for input, expected := range cases {
		if actual := resourceAddress(input); actual != expected {
			t.Errorf("%s: got %s, want %s", input, actual, expected)
		}
	}
}
