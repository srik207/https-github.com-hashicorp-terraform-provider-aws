package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/terraform-providers/terraform-provider-aws/atest"
)

func TestAccDataSourceAwsEc2LocalGatewayRouteTables_basic(t *testing.T) {
	dataSourceName := "data.aws_ec2_local_gateway_route_tables.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:   func() { atest.PreCheck(t); testAccPreCheckAWSOutpostsOutposts(t) },
		ErrorCheck: atest.ErrorCheck(t, ec2.EndpointsID),
		Providers:  atest.Providers,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAwsEc2LocalGatewayRouteTablesConfig(),
				Check: resource.ComposeTestCheckFunc(
					testCheckResourceAttrGreaterThanValue(dataSourceName, "ids.#", "0"),
				),
			},
		},
	})
}

func TestAccDataSourceAwsEc2LocalGatewayRouteTables_Filter(t *testing.T) {
	dataSourceName := "data.aws_ec2_local_gateway_route_tables.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:   func() { atest.PreCheck(t); testAccPreCheckAWSOutpostsOutposts(t) },
		ErrorCheck: atest.ErrorCheck(t, ec2.EndpointsID),
		Providers:  atest.Providers,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAwsEc2LocalGatewayRouteTablesConfigFilter(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "ids.#", "1"),
				),
			},
		},
	})
}

func testAccDataSourceAwsEc2LocalGatewayRouteTablesConfig() string {
	return `
data "aws_ec2_local_gateway_route_tables" "test" {}
`
}

func testAccDataSourceAwsEc2LocalGatewayRouteTablesConfigFilter() string {
	return `
data "aws_ec2_local_gateway_route_tables" "all" {}

data "aws_ec2_local_gateway_route_tables" "test" {
  filter {
    name   = "local-gateway-route-table-id"
    values = [tolist(data.aws_ec2_local_gateway_route_tables.all.ids)[0]]
  }
}
`
}
