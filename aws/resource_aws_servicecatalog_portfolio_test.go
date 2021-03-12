package aws

import (
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/servicecatalog"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"testing"
)

func TestAccAWSServiceCatalogPortfolio_basic(t *testing.T) {
	resourceName := "aws_servicecatalog_portfolio.test"
	saltedName := "tf-acc-test-" + acctest.RandString(5) // RandomWithPrefix exceeds max length 20
	var dpo servicecatalog.DescribePortfolioOutput

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAwsServiceCatalogPortfolioDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSServiceCatalogPortfolioConfig_basic(saltedName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAwsPortfolioExists(resourceName, &dpo),
					testAccMatchResourceAttrRegionalARN(resourceName, "arn", "catalog", regexp.MustCompile(`portfolio/.+`)),
					resource.TestCheckResourceAttrSet(resourceName, "created_time"),
					resource.TestCheckResourceAttr(resourceName, "name", saltedName),
					resource.TestCheckResourceAttr(resourceName, "description", "test-2"),
					resource.TestCheckResourceAttr(resourceName, "provider_name", "test-3"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSServiceCatalogPortfolio_tags(t *testing.T) {
	resourceName := "aws_servicecatalog_portfolio.test"
	saltedName := "tf-acc-test-" + acctest.RandString(5) // RandomWithPrefix exceeds max length 20
	var dpo servicecatalog.DescribePortfolioOutput

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAwsServiceCatalogPortfolioDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSServiceCatalogPortfolioConfig_tags1(saltedName, "key1", "value1"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAwsPortfolioExists(resourceName, &dpo),
					resource.TestCheckResourceAttr(resourceName, "name", saltedName),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.key1", "value1"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccAWSServiceCatalogPortfolioConfig_tags2(saltedName, "key1", "value1updated", "key2", "value2"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAwsPortfolioExists(resourceName, &dpo),
					resource.TestCheckResourceAttr(resourceName, "name", saltedName),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.key1", "value1updated"),
					resource.TestCheckResourceAttr(resourceName, "tags.key2", "value2"),
				),
			},
			{
				Config: testAccAWSServiceCatalogPortfolioConfig_tags1(saltedName, "key2", "value2"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAwsPortfolioExists(resourceName, &dpo),
					resource.TestCheckResourceAttr(resourceName, "name", saltedName),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.key2", "value2"),
				),
			},
		},
	})
}

func testAccCheckAwsPortfolioExists(pr string, dpo *servicecatalog.DescribePortfolioOutput) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := testAccProvider.Meta().(*AWSClient).scconn
		rs, ok := s.RootModule().Resources[pr]
		if !ok {
			return fmt.Errorf("Not found: %s", pr)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		input := servicecatalog.DescribePortfolioInput{}
		input.Id = aws.String(rs.Primary.ID)

		resp, err := conn.DescribePortfolio(&input)
		if err != nil {
			return err
		}

		*dpo = *resp
		return nil
	}
}

func testAccCheckAwsServiceCatalogPortfolioDestroy(s *terraform.State) error {
	conn := testAccProvider.Meta().(*AWSClient).scconn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_servicecatalog_portfolio" {
			continue
		}
		input := servicecatalog.DescribePortfolioInput{}
		input.Id = aws.String(rs.Primary.ID)

		_, err := conn.DescribePortfolio(&input)
		if err == nil {
			return fmt.Errorf("Portfolio still exists")
		}
	}

	return nil
}

func testAccAWSServiceCatalogPortfolioConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "aws_servicecatalog_portfolio" "test" {
  name          = "%s"
  description   = "test-2"
  provider_name = "test-3"
}
`, name)
}

func testAccAWSServiceCatalogPortfolioConfig_tags1(name, tagKey1, tagValue1 string) string {
	return fmt.Sprintf(`
resource "aws_servicecatalog_portfolio" "test" {
  name          = %[1]q
  description   = "test-2"
  provider_name = "test-3"

  tags = {
    %[2]q = %[3]q
  }
}
`, name, tagKey1, tagValue1)
}

func testAccAWSServiceCatalogPortfolioConfig_tags2(name, tagKey1, tagValue1, tagKey2, tagValue2 string) string {
	return fmt.Sprintf(`
resource "aws_servicecatalog_portfolio" "test" {
  name          = %[1]q
  description   = "test-2"
  provider_name = "test-3"

  tags = {
    %[2]q = %[3]q
    %[4]q = %[5]q
  }
}
`, name, tagKey1, tagValue1, tagKey2, tagValue2)
}
