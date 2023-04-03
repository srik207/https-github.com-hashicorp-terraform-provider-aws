package quicksight_test

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/quicksight"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	tfquicksight "github.com/hashicorp/terraform-provider-aws/internal/service/quicksight"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccQuickSightFolder_basic(t *testing.T) {
	ctx := acctest.Context(t)
	var folder quicksight.DescribeFolderOutput
	rId := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_quicksight_folder.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, quicksight.EndpointsID)
		},
		ErrorCheck:               acctest.ErrorCheck(t, quicksight.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckFolderDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccFolderConfig_basic(rId, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFolderExists(ctx, resourceName, &folder),
					resource.TestCheckResourceAttr(resourceName, "folder_id", rId),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "folder_type", quicksight.FolderTypeShared),
					acctest.CheckResourceAttrRegionalARN(resourceName, "arn", "quicksight", fmt.Sprintf("folder/%s", rId)),
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

func TestAccQuickSightFolder_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	var folder quicksight.DescribeFolderOutput
	rId := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_quicksight_folder.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, quicksight.EndpointsID)
		},
		ErrorCheck:               acctest.ErrorCheck(t, quicksight.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckFolderDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccFolderConfig_basic(rId, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFolderExists(ctx, resourceName, &folder),
					acctest.CheckResourceDisappears(ctx, acctest.Provider, tfquicksight.ResourceFolder(), resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccQuickSightFolder_permissions(t *testing.T) {
	ctx := acctest.Context(t)
	var folder quicksight.DescribeFolderOutput
	resourceName := "aws_quicksight_folder.test"
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rId := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, quicksight.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckFolderDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccFolderConfig_permissions(rId, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFolderExists(ctx, resourceName, &folder),
					resource.TestCheckResourceAttr(resourceName, "permissions.#", "1"),
					resource.TestMatchTypeSetElemNestedAttrs(resourceName, "permissions.*", map[string]*regexp.Regexp{
						"principal": regexp.MustCompile(fmt.Sprintf(`user/default/%s`, rName)),
					}),
					resource.TestCheckTypeSetElemAttr(resourceName, "permissions.*.actions.*", "quicksight:DescribeFolder"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccFolderConfig_permissionsUpdate(rId, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFolderExists(ctx, resourceName, &folder),
					resource.TestCheckResourceAttr(resourceName, "permissions.#", "1"),
					resource.TestMatchTypeSetElemNestedAttrs(resourceName, "permissions.*", map[string]*regexp.Regexp{
						"principal": regexp.MustCompile(fmt.Sprintf(`user/default/%s`, rName)),
					}),
					resource.TestCheckTypeSetElemAttr(resourceName, "permissions.*.actions.*", "quicksight:CreateFolder"),
					resource.TestCheckTypeSetElemAttr(resourceName, "permissions.*.actions.*", "quicksight:DescribeFolder"),
					resource.TestCheckTypeSetElemAttr(resourceName, "permissions.*.actions.*", "quicksight:UpdateFolder"),
					resource.TestCheckTypeSetElemAttr(resourceName, "permissions.*.actions.*", "quicksight:DeleteFolder"),
					resource.TestCheckTypeSetElemAttr(resourceName, "permissions.*.actions.*", "quicksight:CreateFolderMembership"),
					resource.TestCheckTypeSetElemAttr(resourceName, "permissions.*.actions.*", "quicksight:DeleteFolderMembership"),
					resource.TestCheckTypeSetElemAttr(resourceName, "permissions.*.actions.*", "quicksight:DescribeFolderPermissions"),
					resource.TestCheckTypeSetElemAttr(resourceName, "permissions.*.actions.*", "quicksight:UpdateFolderPermissions"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccFolderConfig_basic(rId, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFolderExists(ctx, resourceName, &folder),
					resource.TestCheckResourceAttr(resourceName, "permission.#", "0"),
				),
			},
		},
	})
}

func TestAccQuickSightFolder_tags(t *testing.T) {
	ctx := acctest.Context(t)
	var folder quicksight.DescribeFolderOutput
	rId := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_quicksight_folder.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, quicksight.EndpointsID)
		},
		ErrorCheck:               acctest.ErrorCheck(t, quicksight.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckFolderDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccFolderConfig_tags(rId, rName, "key1", "value1"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFolderExists(ctx, resourceName, &folder),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.key1", "value1"),
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

func TestAccQuickSightFolder_parentFolder(t *testing.T) {
	ctx := acctest.Context(t)
	var folder quicksight.DescribeFolderOutput
	rId := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_quicksight_folder.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, quicksight.EndpointsID)
		},
		ErrorCheck:               acctest.ErrorCheck(t, quicksight.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckFolderDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccFolderConfig_parentFolder(rId, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckFolderExists(ctx, resourceName, &folder),
					acctest.CheckResourceAttrRegionalARN(resourceName, "parent_folder_arn", "quicksight", fmt.Sprintf("folder/%s", rId+"-parent")),
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

func testAccCheckFolderDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).QuickSightConn()

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_quicksight_folder" {
				continue
			}

			awsAccountId, folderId, err := tfquicksight.ParseFolderId(rs.Primary.ID)
			if err != nil {
				return err
			}
			output, err := conn.DescribeFolderWithContext(ctx, &quicksight.DescribeFolderInput{
				AwsAccountId: aws.String(awsAccountId),
				FolderId:     aws.String(folderId),
			})
			if err != nil {
				if tfawserr.ErrCodeEquals(err, quicksight.ErrCodeResourceNotFoundException) {
					return nil
				}
				return err
			}

			if output != nil && output.Folder != nil {
				return fmt.Errorf("QuickSight Folder (%s) still exists", rs.Primary.ID)
			}
		}

		return nil
	}
}

func testAccCheckFolderExists(ctx context.Context, name string, folder *quicksight.DescribeFolderOutput) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return create.Error(names.QuickSight, create.ErrActionCheckingExistence, tfquicksight.ResNameFolder, name, errors.New("not found"))
		}

		if rs.Primary.ID == "" {
			return create.Error(names.QuickSight, create.ErrActionCheckingExistence, tfquicksight.ResNameFolder, name, errors.New("not set"))
		}

		awsAccountId, folderId, err := tfquicksight.ParseFolderId(rs.Primary.ID)
		if err != nil {
			return err
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).QuickSightConn()
		resp, err := conn.DescribeFolderWithContext(ctx, &quicksight.DescribeFolderInput{
			AwsAccountId: aws.String(awsAccountId),
			FolderId:     aws.String(folderId),
		})

		if err != nil {
			return create.Error(names.QuickSight, create.ErrActionCheckingExistence, tfquicksight.ResNameFolder, rs.Primary.ID, err)
		}

		*folder = *resp

		return nil
	}
}

func testAccFolderConfig_basic(rId, rName string) string {
	return fmt.Sprintf(`
resource "aws_quicksight_folder" "test" {
  folder_id = %[1]q
  name      = %[2]q
}
`, rId, rName)
}

func testAccFolderConfig_user(rName string) string {
	return fmt.Sprintf(`
data "aws_caller_identity" "current" {}

resource "aws_quicksight_user" "test" {
  aws_account_id = data.aws_caller_identity.current.account_id
  user_name      = %[1]q
  email          = %[2]q
  identity_type  = "QUICKSIGHT"
  user_role      = "AUTHOR"

  lifecycle {
    create_before_destroy = true
  }
}
`, rName, acctest.DefaultEmailAddress)
}

func testAccFolderConfig_permissions(rId, rName string) string {
	return acctest.ConfigCompose(
		testAccFolderConfig_user(rName),
		fmt.Sprintf(`
resource "aws_quicksight_folder" "test" {
  folder_id = %[1]q
  name      = %[2]q
  permissions {
    actions = [
      "quicksight:DescribeFolder",
    ]
    principal = aws_quicksight_user.test.arn
  }
}
`, rId, rName))
}

func testAccFolderConfig_permissionsUpdate(rId, rName string) string {
	return acctest.ConfigCompose(
		testAccFolderConfig_user(rName),
		fmt.Sprintf(`
resource "aws_quicksight_folder" "test" {
  folder_id = %[1]q
  name      = %[2]q
  permissions {
    actions = [
      "quicksight:CreateFolder",
      "quicksight:DescribeFolder",
      "quicksight:UpdateFolder",
      "quicksight:DeleteFolder",
      "quicksight:CreateFolderMembership",
      "quicksight:DeleteFolderMembership",
      "quicksight:DescribeFolderPermissions",
      "quicksight:UpdateFolderPermissions",
    ]
    principal = aws_quicksight_user.test.arn
  }
}
`, rId, rName))
}

func testAccFolderConfig_tags(rId, rName, key, value string) string {
	return fmt.Sprintf(`
resource "aws_quicksight_folder" "test" {
  folder_id = %[1]q
  name      = %[2]q

  tags = {
    %[3]q = %[4]q
  }
}
`, rId, rName, key, value)
}

func testAccFolderConfig_parentFolder(rId, rName string) string {
	parentId := rId + "-parent"
	parentName := rName + "-parent"
	return fmt.Sprintf(`
resource "aws_quicksight_folder" "parent" {
  folder_id = %[1]q
  name      = %[2]q
}

resource "aws_quicksight_folder" "test" {
  folder_id         = %[3]q
  name              = %[4]q
  parent_folder_arn = aws_quicksight_folder.parent.arn
}
`, parentId, parentName, rId, rName)
}
