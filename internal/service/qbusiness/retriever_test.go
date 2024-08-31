// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package qbusiness_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/qbusiness"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tfqbusiness "github.com/hashicorp/terraform-provider-aws/internal/service/qbusiness"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccQBusinessRetriever_basic(t *testing.T) {
	ctx := acctest.Context(t)
	var retriever qbusiness.GetRetrieverOutput
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_qbusiness_retriever.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheckRetriever(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, "qbusiness"),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckRetrieverDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccRetrieverConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckRetrieverExists(ctx, resourceName, &retriever),
					resource.TestCheckResourceAttrSet(resourceName, "retriever_id"),
					resource.TestCheckResourceAttrSet(resourceName, names.AttrARN),
					resource.TestCheckResourceAttrSet(resourceName, names.AttrType),
					resource.TestCheckResourceAttr(resourceName, names.AttrDisplayName, rName),
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

func TestAccQBusinessRetriever_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	var retriever qbusiness.GetRetrieverOutput
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_qbusiness_retriever.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheckRetriever(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, "qbusiness"),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckRetrieverDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccRetrieverConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckRetrieverExists(ctx, resourceName, &retriever),
					acctest.CheckFrameworkResourceDisappears(ctx, acctest.Provider, tfqbusiness.ResourceRetriever, resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccQBusinessRetriever_tags(t *testing.T) {
	ctx := acctest.Context(t)
	var retriever qbusiness.GetRetrieverOutput
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_qbusiness_retriever.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheckRetriever(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, "qbusiness"),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckRetrieverDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccRetrieverConfig_tags(rName, acctest.CtKey1, acctest.CtValue1, acctest.CtKey2, acctest.CtValue2),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckRetrieverExists(ctx, resourceName, &retriever),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, acctest.Ct2),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey1, acctest.CtValue1),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey2, acctest.CtValue2),
				),
			},
			{
				Config: testAccRetrieverConfig_tags(rName, acctest.CtKey1, acctest.CtValue1Updated, acctest.CtKey2, "value2updated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckRetrieverExists(ctx, resourceName, &retriever),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey1, acctest.CtValue1Updated),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey2, "value2updated"),
				),
			},
		},
	})
}

func TestAccQBusinessRetriever_boostOverrides(t *testing.T) {
	ctx := acctest.Context(t)
	var retriever qbusiness.GetRetrieverOutput
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_qbusiness_retriever.test"
	boostLevel1 := "HIGH"
	boostLevel2 := "VERY_HIGH"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheckRetriever(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, "qbusiness"),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckRetrieverDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccRetrieverConfig_boostOverrides(rName, boostLevel1),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckRetrieverExists(ctx, resourceName, &retriever),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.string_boost_override.#", acctest.Ct1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.string_list_boost_override.#", acctest.Ct1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.number_boost_override.#", acctest.Ct1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.date_boost_override.#", acctest.Ct1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.string_boost_override.0.boosting_level", boostLevel1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.string_list_boost_override.0.boosting_level", boostLevel1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.number_boost_override.0.boosting_level", boostLevel1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.date_boost_override.0.boosting_level", boostLevel1),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccRetrieverConfig_boostOverrides(rName, boostLevel2),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckRetrieverExists(ctx, resourceName, &retriever),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.string_boost_override.#", acctest.Ct1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.string_list_boost_override.#", acctest.Ct1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.number_boost_override.#", acctest.Ct1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.date_boost_override.#", acctest.Ct1),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.string_boost_override.0.boosting_level", boostLevel2),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.string_list_boost_override.0.boosting_level", boostLevel2),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.number_boost_override.0.boosting_level", boostLevel2),
					resource.TestCheckResourceAttr(resourceName, "native_index_configuration.date_boost_override.0.boosting_level", boostLevel2),
				),
			},
		},
	})
}

func testAccPreCheckRetriever(ctx context.Context, t *testing.T) {
	conn := acctest.Provider.Meta().(*conns.AWSClient).QBusinessClient(ctx)

	input := &qbusiness.ListApplicationsInput{}

	_, err := conn.ListApplications(ctx, input)

	if acctest.PreCheckSkipError(err) {
		t.Skipf("skipping acceptance testing: %s", err)
	}

	if err != nil {
		t.Fatalf("unexpected PreCheck error: %s", err)
	}
}

func testAccCheckRetrieverDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).QBusinessClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_qbusiness_retriever" {
				continue
			}

			_, err := tfqbusiness.FindRetrieverByID(ctx, conn, rs.Primary.ID)

			if tfresource.NotFound(err) {
				continue
			}

			if err != nil {
				return err
			}

			return fmt.Errorf("Amazon Q Retriever %s still exists", rs.Primary.ID)
		}

		return nil
	}
}

func testAccCheckRetrieverExists(ctx context.Context, n string, v *qbusiness.GetRetrieverOutput) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).QBusinessClient(ctx)

		output, err := tfqbusiness.FindRetrieverByID(ctx, conn, rs.Primary.ID)

		if err != nil {
			return err
		}

		*v = *output

		return nil
	}
}

func testAccRetrieverConfig_basic(rName string) string {
	return acctest.ConfigCompose(testAccIndexConfig_basic(rName), fmt.Sprintf(`
resource "aws_qbusiness_retriever" "test" {
  application_id = aws_qbusiness_app.test.id
  display_name   = %[1]q
  type           = "NATIVE_INDEX"

  native_index_configuration {
    index_id = aws_qbusiness_index.test.index_id
  }
}
`, rName))
}

func testAccRetrieverConfig_boostOverrides(rName, boostingLevel string) string {
	return acctest.ConfigCompose(testAccAppConfig_basic(rName), fmt.Sprintf(`
resource "aws_qbusiness_index" "test" {
  application_id = aws_qbusiness_app.test.id
  display_name   = %[1]q

  capacity_configuration {
    units = 1
  }
  document_attribute_configuration {
    name   = "date"
    search = "DISABLED"
    type   = "DATE"
  }
  document_attribute_configuration {
    name   = "number"
    search = "DISABLED"
    type   = "NUMBER"
  }
  document_attribute_configuration {
    name   = "string"
    search = "ENABLED"
    type   = "STRING"
  }
  document_attribute_configuration {
    name   = "string_list"
    search = "ENABLED"
    type   = "STRING_LIST"
  }
}

resource "aws_qbusiness_retriever" "test" {
  application_id = aws_qbusiness_app.test.id
  display_name   = %[1]q
  type           = "NATIVE_INDEX"

  native_index_configuration {
    index_id = aws_qbusiness_index.test.index_id

    string_boost_override {
      boost_key      = "string"
      boosting_level = %[2]q

      attribute_value_boosting = {
        "key1" = "VERY_HIGH"
        "key2" = "VERY_HIGH"
      }
    }

    string_list_boost_override {
      boost_key      = "string_list"
      boosting_level = %[2]q
    }

    date_boost_override {
      boost_key         = "date"
      boosting_level    = %[2]q
      boosting_duration = 100
    }

    number_boost_override {
      boost_key      = "number"
      boosting_level = %[2]q
      boosting_type  = "PRIORITIZE_LARGER_VALUES"
    }
  }
}
`, rName, boostingLevel))
}

func testAccRetrieverConfig_tags(rName, tagKey1, tagValue1, tagKey2, tagValue2 string) string {
	return acctest.ConfigCompose(testAccIndexConfig_basic(rName), fmt.Sprintf(`
resource "aws_qbusiness_retriever" "test" {
  application_id = aws_qbusiness_app.test.id
  display_name   = %[1]q
  type           = "NATIVE_INDEX"

  native_index_configuration {
    index_id = aws_qbusiness_index.test.index_id
  }

  tags = {
    %[2]q = %[3]q
    %[4]q = %[5]q
  }
}
`, rName, tagKey1, tagValue1, tagKey2, tagValue2))
}
