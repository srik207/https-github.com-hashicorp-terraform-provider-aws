package aws

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/servicecatalog"
	multierror "github.com/hashicorp/go-multierror"
	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	tfservicecatalog "github.com/hashicorp/terraform-provider-aws/aws/internal/service/servicecatalog"
	"github.com/hashicorp/terraform-provider-aws/aws/internal/service/servicecatalog/waiter"
	"github.com/hashicorp/terraform-provider-aws/aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/provider"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
)

// add sweeper to delete known test servicecat product portfolio associations
func init() {
	resource.AddTestSweepers("aws_servicecatalog_product_portfolio_association", &resource.Sweeper{
		Name:         "aws_servicecatalog_product_portfolio_association",
		Dependencies: []string{},
		F:            testSweepServiceCatalogProductPortfolioAssociations,
	})
}

func testSweepServiceCatalogProductPortfolioAssociations(region string) error {
	client, err := acctest.SharedRegionalSweeperClient(region)

	if err != nil {
		return fmt.Errorf("error getting client: %s", err)
	}

	conn := client.(*conns.AWSClient).ServiceCatalogConn
	sweepResources := make([]*acctest.SweepResource, 0)
	var errs *multierror.Error

	// no paginator or list operation for associations directly, have to list products and associations of products

	input := &servicecatalog.SearchProductsAsAdminInput{}

	err = conn.SearchProductsAsAdminPages(input, func(page *servicecatalog.SearchProductsAsAdminOutput, lastPage bool) bool {
		if page == nil {
			return !lastPage
		}

		for _, detail := range page.ProductViewDetails {
			if detail == nil {
				continue
			}

			productARN, err := arn.Parse(aws.StringValue(detail.ProductARN))

			if err != nil {
				errs = multierror.Append(errs, fmt.Errorf("error parsing Product ARN for %s: %w", aws.StringValue(detail.ProductARN), err))
				continue
			}

			// arn:aws:catalog:us-west-2:187416307283:product/prod-t5thhvquxw2x2

			resourceParts := strings.SplitN(productARN.Resource, "/", 2)

			if len(resourceParts) != 2 {
				errs = multierror.Append(errs, fmt.Errorf("error parsing Product ARN resource for %s: %w", aws.StringValue(detail.ProductARN), err))
				continue
			}

			productID := resourceParts[1]

			assocInput := &servicecatalog.ListPortfoliosForProductInput{
				ProductId: aws.String(productID),
			}

			err = conn.ListPortfoliosForProductPages(assocInput, func(page *servicecatalog.ListPortfoliosForProductOutput, lastPage bool) bool {
				if page == nil {
					return !lastPage
				}

				for _, detail := range page.PortfolioDetails {
					if detail == nil {
						continue
					}

					r := ResourceProductPortfolioAssociation()
					d := r.Data(nil)
					d.SetId(tfservicecatalog.ProductPortfolioAssociationCreateID(tfservicecatalog.AcceptLanguageEnglish, aws.StringValue(detail.Id), productID))

					sweepResources = append(sweepResources, acctest.NewSweepResource(r, d, client))
				}

				return !lastPage
			})

			if err != nil {
				errs = multierror.Append(errs, fmt.Errorf("error listing Service Catalog Portfolios for Products %s: %w", region, err))
				continue
			}
		}

		return !lastPage
	})

	if err != nil {
		errs = multierror.Append(errs, fmt.Errorf("error describing Service Catalog Product Portfolio Associations for %s: %w", region, err))
	}

	if err = acctest.SweepOrchestrator(sweepResources); err != nil {
		errs = multierror.Append(errs, fmt.Errorf("error sweeping Service Catalog Product Portfolio Associations for %s: %w", region, err))
	}

	if acctest.SkipSweepError(errs.ErrorOrNil()) {
		log.Printf("[WARN] Skipping Service Catalog Product Portfolio Associations sweep for %s: %s", region, errs)
		return nil
	}

	return errs.ErrorOrNil()
}

func TestAccAWSServiceCatalogProductPortfolioAssociation_basic(t *testing.T) {
	resourceName := "aws_servicecatalog_product_portfolio_association.test"
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	domain := fmt.Sprintf("http://%s", acctest.RandomDomainName())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, servicecatalog.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckAwsServiceCatalogProductPortfolioAssociationDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSServiceCatalogProductPortfolioAssociationConfig_basic(rName, domain, acctest.DefaultEmailAddress),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAwsServiceCatalogProductPortfolioAssociationExists(resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "portfolio_id", "aws_servicecatalog_portfolio.test", "id"),
					resource.TestCheckResourceAttrPair(resourceName, "product_id", "aws_servicecatalog_product.test", "id"),
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

func TestAccAWSServiceCatalogProductPortfolioAssociation_disappears(t *testing.T) {
	resourceName := "aws_servicecatalog_product_portfolio_association.test"
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	domain := fmt.Sprintf("http://%s", acctest.RandomDomainName())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, servicecatalog.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckAwsServiceCatalogProductPortfolioAssociationDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSServiceCatalogProductPortfolioAssociationConfig_basic(rName, domain, acctest.DefaultEmailAddress),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAwsServiceCatalogProductPortfolioAssociationExists(resourceName),
					acctest.CheckResourceDisappears(acctest.Provider, ResourceProductPortfolioAssociation(), resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckAwsServiceCatalogProductPortfolioAssociationDestroy(s *terraform.State) error {
	conn := acctest.Provider.Meta().(*conns.AWSClient).ServiceCatalogConn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_servicecatalog_product_portfolio_association" {
			continue
		}

		acceptLanguage, portfolioID, productID, err := tfservicecatalog.ProductPortfolioAssociationParseID(rs.Primary.ID)

		if err != nil {
			return fmt.Errorf("could not parse ID (%s): %w", rs.Primary.ID, err)
		}

		err = waiter.ProductPortfolioAssociationDeleted(conn, acceptLanguage, portfolioID, productID)

		if tfresource.NotFound(err) {
			continue
		}

		if err != nil {
			return fmt.Errorf("waiting for Service Catalog Product Portfolio Association to be destroyed (%s): %w", rs.Primary.ID, err)
		}
	}

	return nil
}

func testAccCheckAwsServiceCatalogProductPortfolioAssociationExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]

		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		acceptLanguage, portfolioID, productID, err := tfservicecatalog.ProductPortfolioAssociationParseID(rs.Primary.ID)

		if err != nil {
			return fmt.Errorf("could not parse ID (%s): %w", rs.Primary.ID, err)
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).ServiceCatalogConn

		_, err = waiter.ProductPortfolioAssociationReady(conn, acceptLanguage, portfolioID, productID)

		if err != nil {
			return fmt.Errorf("waiting for Service Catalog Product Portfolio Association existence (%s): %w", rs.Primary.ID, err)
		}

		return nil
	}
}

func testAccAWSServiceCatalogProductPortfolioAssociationConfig_base(rName, domain, email string) string {
	return fmt.Sprintf(`
resource "aws_cloudformation_stack" "test" {
  name = %[1]q

  template_body = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"

    Resources = {
      MyVPC = {
        Type = "AWS::EC2::VPC"
        Properties = {
          CidrBlock = "10.1.0.0/16"
        }
      }
    }

    Outputs = {
      VpcID = {
        Description = "VPC ID"
        Value = {
          Ref = "MyVPC"
        }
      }
    }
  })
}

resource "aws_servicecatalog_product" "test" {
  description         = "beskrivning"
  distributor         = "distributör"
  name                = %[1]q
  owner               = "ägare"
  type                = "CLOUD_FORMATION_TEMPLATE"
  support_description = "supportbeskrivning"
  support_email       = %[3]q
  support_url         = %[2]q

  provisioning_artifact_parameters {
    description          = "artefaktbeskrivning"
    name                 = %[1]q
    template_physical_id = aws_cloudformation_stack.test.id
    type                 = "CLOUD_FORMATION_TEMPLATE"
  }

  tags = {
    Name = %[1]q
  }
}

resource "aws_servicecatalog_portfolio" "test" {
  name          = %[1]q
  provider_name = %[1]q
}
`, rName, domain, email)
}

func testAccAWSServiceCatalogProductPortfolioAssociationConfig_basic(rName, domain, email string) string {
	return acctest.ConfigCompose(testAccAWSServiceCatalogProductPortfolioAssociationConfig_base(rName, domain, email), `
resource "aws_servicecatalog_product_portfolio_association" "test" {
  portfolio_id = aws_servicecatalog_portfolio.test.id
  product_id   = aws_servicecatalog_product.test.id
}
`)
}
