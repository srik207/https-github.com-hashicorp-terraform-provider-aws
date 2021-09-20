// Code generated by internal/tagresource/generator/main.go; DO NOT EDIT.

package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-aws/aws/internal/keyvaluetags"
	"github.com/hashicorp/terraform-provider-aws/aws/internal/tagresource"
	"github.com/hashicorp/terraform-provider-aws/aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
)

func testAccCheckDynamodbTagDestroy(s *terraform.State) error {
	conn := acctest.Provider.Meta().(*conns.AWSClient).DynamoDBConn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_dynamodb_tag" {
			continue
		}

		identifier, key, err := tagresource.GetResourceID(rs.Primary.ID)

		if err != nil {
			return err
		}

		_, err = keyvaluetags.DynamodbGetTag(conn, identifier, key)

		if tfresource.NotFound(err) {
			continue
		}

		if err != nil {
			return err
		}

		return fmt.Errorf("%s resource (%s) tag (%s) still exists", dynamodb.ServiceID, identifier, key)
	}

	return nil
}

func testAccCheckDynamodbTagExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("%s: missing resource ID", resourceName)
		}

		identifier, key, err := tagresource.GetResourceID(rs.Primary.ID)

		if err != nil {
			return err
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).DynamoDBConn

		_, err = keyvaluetags.DynamodbGetTag(conn, identifier, key)

		if err != nil {
			return err
		}

		return nil
	}
}
