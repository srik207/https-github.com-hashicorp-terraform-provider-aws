// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bedrock_test

import (
	"fmt"
	"testing"

	// "github.com/aws/aws-sdk-go/service/bedrock"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
)

func TestAccCustomModel_basic(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	// customModelResourceName := "aws_bedrock_custom_model.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() { acctest.PreCheck(ctx, t) },
		// ErrorCheck:               acctest.ErrorCheck(t, eks.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomModelConfig_basic(rName),
				Check:  resource.ComposeAggregateTestCheckFunc(
				// testAccCheckAddonExists(ctx, customModelResourceName, &addon),
				// resource.TestCheckResourceAttr(customModelResourceName, "addon_name", addonName),
				// resource.TestCheckResourceAttrSet(customModelResourceName, "addon_version"),
				// acctest.MatchResourceAttrRegionalARN(customModelResourceName, "arn", "eks", regexache.MustCompile(fmt.Sprintf("addon/%s/%s/.+$", rName, addonName))),
				// resource.TestCheckResourceAttr(customModelResourceName, "configuration_values", ""),
				// resource.TestCheckNoResourceAttr(customModelResourceName, "preserve"),
				// resource.TestCheckResourceAttr(customModelResourceName, "tags.%", "0"),
				),
			},
			// {
			// 	ResourceName:      customModelResourceName,
			// 	ImportState:       true,
			// 	ImportStateVerify: true,
			// },
		},
	})
}

// func TestAccCustomModel_disappears(t *testing.T) {
// 	ctx := acctest.Context(t)
// 	var addon eks.Addon
// 	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
// 	resourceName := "aws_eks_addon.test"
// 	addonName := "vpc-cni"

// 	resource.ParallelTest(t, resource.TestCase{
// 		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
// 		ErrorCheck:               acctest.ErrorCheck(t, eks.EndpointsID),
// 		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
// 		CheckDestroy:             testAccCheckAddonDestroy(ctx),
// 		Steps: []resource.TestStep{
// 			{
// 				Config: testAccCustomModelConfig_basic(rName, addonName),
// 				Check: resource.ComposeTestCheckFunc(
// 					testAccCheckAddonExists(ctx, resourceName, &addon),
// 					acctest.CheckResourceDisappears(ctx, acctest.Provider, tfeks.ResourceAddon(), resourceName),
// 				),
// 				ExpectNonEmptyPlan: true,
// 			},
// 		},
// 	})
// }

func testAccCustomModelConfig_basic(rName string) string {
	return fmt.Sprintf(`
data "aws_caller_identity" "current" {}

resource aws_s3_bucket training_data {
	bucket = "bedrock-training-data-%[1]s"
	tags = {
		"CreatorName" = "richard.weerasinghe@slalom.com"
	}
}

resource aws_s3_bucket validation_data {
	bucket = "bedrock-validation-data-%[1]s"
	tags = {
		"CreatorName" = "richard.weerasinghe@slalom.com"
	}
}

resource aws_s3_bucket output_data {
	bucket = "bedrock-output-data-%[1]s"
	tags = {
		"CreatorName" = "richard.weerasinghe@slalom.com"
	}
}

resource "aws_iam_role" "bedrock_fine_tuning" {
	name = "examplerole"
  
	assume_role_policy = <<EOF
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Principal": {
				"Service": "bedrock.amazonaws.com"
			},
			"Action": "sts:AssumeRole",
			"Condition": {
				"StringEquals": {
					"aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
				},
				"ArnEquals": {
					"aws:SourceArn": "arn:aws:bedrock:us-east-1:${data.aws_caller_identity.current.account_id}:model-customization-job/*"
				}
			}
		}
	] 
}
EOF
}

resource "aws_iam_policy" "BedrockAccessTrainingValidationS3Policy" {
	name        = "BedrockAccessTrainingValidationS3Policy_%[1]s"
	path        = "/"
	description = "BedrockAccessTrainingValidationS3Policy"

	policy = jsonencode({
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": [
					"s3:GetObject",
					"s3:PutObject",
					"s3:ListBucket",
					"s3:ListObjects"
				],
				"Resource": [
					"${aws_s3_bucket.training_data.arn}/myfolder",
					"${aws_s3_bucket.training_data.arn}/myfolder/*",
					"${aws_s3_bucket.validation_data.arn}/myfolder",
					"${aws_s3_bucket.validation_data.arn}/myfolder/*"
				]
			}
		]
	})
}

resource "aws_iam_policy" "BedrockAccessOutputS3Policy" {
	name        = "BedrockAccessOutputS3Policy_%[1]s"
	path        = "/"
	description = "BedrockAccessOutputS3Policy"

	policy = jsonencode({
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": [
					"s3:GetObject",
					"s3:PutObject",
					"s3:ListBucket",
					"s3:ListObjects"
				],
				"Resource": [
					"${aws_s3_bucket.output_data.arn}/myfolder",
					"${aws_s3_bucket.output_data.arn}/myfolder/*"
				]
			}
		]
	})
}

resource "aws_iam_role_policy_attachment" "bedrock_attachment_1" {
	role       = aws_iam_role.bedrock_fine_tuning.name
	policy_arn = aws_iam_policy.BedrockAccessTrainingValidationS3Policy.arn
}

resource "aws_iam_role_policy_attachment" "bedrock_attachment_2" {
	role       = aws_iam_role.bedrock_fine_tuning.name
	policy_arn = aws_iam_policy.BedrockAccessOutputS3Policy.arn
}
  
data "aws_bedrock_foundation_models" "test" {}

resource "aws_bedrock_custom_model" "test" {
	custom_model_name = %[1]q
	job_name = %[1]q
	base_model_id = data.aws_bedrock_foundation_models.test.model_summaries[0].model_id
	hyper_parameters = {
	  "epochCount" = "1"
	  "batchSize" = "1"
	  "learningRate" = "0.005"
	  "learningRateWarmupSteps" = "0"
	}
	output_data_config = "s3://${aws_s3_bucket.output_data.id}/myfolder/"
	role_arn = aws_iam_role.bedrock_fine_tuning.arn
	training_data_config = "s3://${aws_s3_bucket.training_data.id}/myfolder/"
  }
`, rName)
}
