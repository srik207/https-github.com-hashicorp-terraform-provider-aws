package route53resolver_test

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/route53resolver"
	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
)

func TestAccRoute53ResolverFirewallRulesDataSource_basic(t *testing.T) {
	dataSourceName := "data.aws_route53_resolver_firewall_rules.test"

	propagationSleep := func() resource.TestCheckFunc {
		return func(s *terraform.State) error {
			log.Print("[DEBUG] Test: Sleep to allow firewall rule to be visible in the list.")
			time.Sleep(5 * time.Second)
			return nil
		}
	}

	fqdn := acctest.RandomFQDomainName()
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	action := "ALLOW"
	priority := "100"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:          func() { acctest.PreCheck(t) },
		ErrorCheck:        acctest.ErrorCheck(t, route53resolver.EndpointsID),
		ProviderFactories: acctest.ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallRulesDataSourceConfig_base(rName, fqdn, action, priority),
				Check:  propagationSleep(),
			},
			{
				Config: testAccFirewallRulesDataSourceConfig_basic(rName, fqdn, action, priority),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.action"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.block_override_ttl"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.creation_time"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.creator_request_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.firewall_domain_list_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.firewall_rule_group_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.modification_time"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.priority"),
					resource.TestCheckResourceAttr(dataSourceName, "firewall_rules.0.name", rName),
				),
			},
			{
				Config: testAccFirewallRulesDataSourceConfig_filter(rName, fqdn, action, priority),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.action"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.block_override_ttl"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.creation_time"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.creator_request_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.firewall_domain_list_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.firewall_rule_group_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.modification_time"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.priority"),
					resource.TestCheckResourceAttr(dataSourceName, "firewall_rules.0.name", rName),
				),
			},
			{
				Config: testAccFirewallRulesDataSourceConfig_filter_action(rName, fqdn, action, priority),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.action"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.block_override_ttl"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.creation_time"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.creator_request_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.firewall_domain_list_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.firewall_rule_group_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.modification_time"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.priority"),
					resource.TestCheckResourceAttr(dataSourceName, "firewall_rules.0.name", rName),
				),
			},
			{
				Config: testAccFirewallRulesDataSourceConfig_filter_priority(rName, fqdn, action, priority),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.action"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.block_override_ttl"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.creation_time"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.creator_request_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.firewall_domain_list_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.firewall_rule_group_id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.modification_time"),
					resource.TestCheckResourceAttrSet(dataSourceName, "firewall_rules.0.priority"),
					resource.TestCheckResourceAttr(dataSourceName, "firewall_rules.0.name", rName),
				),
			},
		},
	})
}

func testAccFirewallRulesDataSourceConfig_base(rName, fqdn, action, priority string) string {
	return fmt.Sprintf(`
resource "aws_route53_resolver_firewall_rule_group" "test" {
  name = %[1]q
}

resource "aws_route53_resolver_firewall_domain_list" "test" {
  name    = %[1]q
  domains = [%[2]q]
}

resource "aws_route53_resolver_firewall_rule" "test" {
  name                    = %[1]q
  action                  = %[3]q
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.test.id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.test.id
  priority                = %[4]q
}
`, rName, fqdn, action, priority)
}

func testAccFirewallRulesDataSourceConfig_basic(rName, fqdn, action, priority string) string {
	return acctest.ConfigCompose(testAccFirewallRulesDataSourceConfig_base(rName, fqdn, action, priority), `
data "aws_route53_resolver_firewall_rules" "test" {
  id = aws_route53_resolver_firewall_rule_group.test.id
}
`)
}

func testAccFirewallRulesDataSourceConfig_filter(rName, fqdn, action, priority string) string {
	return acctest.ConfigCompose(testAccFirewallRulesDataSourceConfig_base(rName, fqdn, action, priority), fmt.Sprintf(`
data "aws_route53_resolver_firewall_rules" "test" {
  id = aws_route53_resolver_firewall_rule_group.test.id
  action = %[1]q
  priority = %[2]q
}
`, action, priority))
}

func testAccFirewallRulesDataSourceConfig_filter_action(rName, fqdn, action, priority string) string {
	return acctest.ConfigCompose(testAccFirewallRulesDataSourceConfig_base(rName, fqdn, action, priority), fmt.Sprintf(`
data "aws_route53_resolver_firewall_rules" "test" {
  id = aws_route53_resolver_firewall_rule_group.test.id
  action = %[1]q
}
`, action))
}

func testAccFirewallRulesDataSourceConfig_filter_priority(rName, fqdn, action, priority string) string {
	return acctest.ConfigCompose(testAccFirewallRulesDataSourceConfig_base(rName, fqdn, action, priority), fmt.Sprintf(`
data "aws_route53_resolver_firewall_rules" "test" {
  id = aws_route53_resolver_firewall_rule_group.test.id
  priority = %[1]q
}
`, priority))
}
