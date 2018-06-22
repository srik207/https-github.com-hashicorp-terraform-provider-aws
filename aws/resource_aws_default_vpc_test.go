package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccAWSDefaultVpc_basic(t *testing.T) {
	var vpc ec2.Vpc

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSDefaultVpcDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSDefaultVpcConfigBasic,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVpcExists("aws_default_vpc.foo", &vpc),
					testAccCheckVpcCidr(&vpc, "172.31.0.0/16"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.foo", "cidr_block", "172.31.0.0/16"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.foo", "tags.%", "1"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.foo", "tags.Name", "terraform-testacc-default-vpc"),
				),
			},
		},
	})
}

func TestAccAWSDefaultVpc_enableIpv6(t *testing.T) {
	var vpc ec2.Vpc

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSDefaultVpcDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSDefaultVpcConfigIpv6Enabled,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVpcExists("aws_default_vpc.foo", &vpc),
					testAccCheckVpcCidr(&vpc, "172.31.0.0/16"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.foo", "cidr_block", "172.31.0.0/16"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.foo", "tags.%", "1"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.foo", "tags.Name", "terraform-testacc-default-vpc-ipv6"),
					testAccCheckVpcIpv6(&vpc, true),
				),
			},
			// Ensure that we don't try an associate another Amazon-provided IPv6 CIDR.
			{
				Config: testAccAWSDefaultVpcAltConfigIpv6Enabled,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVpcExists("aws_default_vpc.bar", &vpc),
					testAccCheckVpcCidr(&vpc, "172.31.0.0/16"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.bar", "cidr_block", "172.31.0.0/16"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.bar", "tags.%", "1"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.bar", "tags.Name", "terraform-testacc-default-vpc-ipv6"),
					testAccCheckVpcIpv6(&vpc, true),
				),
			},
			{
				Config: testAccAWSDefaultVpcConfigIpv6Disabled,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVpcExists("aws_default_vpc.foo", &vpc),
					testAccCheckVpcCidr(&vpc, "172.31.0.0/16"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.foo", "assign_generated_ipv6_cidr_block", "false"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.foo", "ipv6_association_id", ""),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.foo", "ipv6_cidr_block", ""),
					testAccCheckVpcIpv6(&vpc, false),
				),
			},
			// Ensure that we don't try an disassociate the Amazon-provided IPv6 CIDR again.
			{
				Config: testAccAWSDefaultVpcAltConfigIpv6Disabled,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVpcExists("aws_default_vpc.baz", &vpc),
					testAccCheckVpcCidr(&vpc, "172.31.0.0/16"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.baz", "assign_generated_ipv6_cidr_block", "false"),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.baz", "ipv6_association_id", ""),
					resource.TestCheckResourceAttr(
						"aws_default_vpc.baz", "ipv6_cidr_block", ""),
					testAccCheckVpcIpv6(&vpc, false),
				),
			},
		},
	})
}

func testAccCheckAWSDefaultVpcDestroy(s *terraform.State) error {
	// We expect VPC to still exist
	return nil
}

const testAccAWSDefaultVpcConfigBasic = `
resource "aws_default_vpc" "foo" {
  tags {
    Name = "terraform-testacc-default-vpc"
  }
}
`

const testAccAWSDefaultVpcConfigIpv6Enabled = `
resource "aws_default_vpc" "foo" {
  assign_generated_ipv6_cidr_block = true
  tags {
    Name = "terraform-testacc-default-vpc-ipv6"
  }
}
`

const testAccAWSDefaultVpcConfigIpv6Disabled = `
resource "aws_default_vpc" "foo" {
  assign_generated_ipv6_cidr_block = false
  tags {
    Name = "terraform-testacc-default-vpc-ipv6"
  }
}
`

const testAccAWSDefaultVpcAltConfigIpv6Enabled = `
resource "aws_default_vpc" "foo" {
  tags {
    Name = "terraform-testacc-default-vpc-ipv6"
  }
}

resource "aws_default_vpc" "bar" {
  assign_generated_ipv6_cidr_block = true
  tags {
    Name = "terraform-testacc-default-vpc-ipv6"
  }
}
`

const testAccAWSDefaultVpcAltConfigIpv6Disabled = `
resource "aws_default_vpc" "foo" {
  tags {
    Name = "terraform-testacc-default-vpc-ipv6"
  }
}

resource "aws_default_vpc" "baz" {
  assign_generated_ipv6_cidr_block = false
  tags {
    Name = "terraform-testacc-default-vpc-ipv6"
  }
}
`
