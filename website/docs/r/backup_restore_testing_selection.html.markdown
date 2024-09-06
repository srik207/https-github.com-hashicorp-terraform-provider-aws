---
subcategory: "Backup"
layout: "aws"
page_title: "AWS: aws_backup_restore_testing_selection"
description: |-
  Terraform resource for managing an AWS Backup Restore Testing Selection.
---

# Resource: aws_backup_restore_testing_selection

Terraform resource for managing an AWS Backup Restore Testing Selection.

## Example Usage

### Basic Usage

```terraform
resource "aws_backup_restore_testing_selection" "example" {
  name = "ec2_selection"

  restore_testing_plan_name = aws_backup_restore_testing_plan.example.name
  protected_resource_type   = "EC2"
  iam_role_arn              = aws_iam_role.example.arn

  protected_resource_conditions {
    string_equals     = []
    string_not_equals = []
  }
}
```

### Advanced Usage

```terraform
resource "aws_backup_restore_testing_selection" "example" {
  name = "ec2_selection"

  restore_testing_plan_name = aws_backup_restore_testing_plan.example.name
  protected_resource_type   = "EC2"
  iam_role_arn              = aws_iam_role.example.arn

  protected_resource_conditions {
    string_equals = [
      {
        key   = "Backup Test",
        value = true
      }
    ]
    string_not_equals = []
  }
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the backup restore testing selection.

* `restore_testing_plan_name` - (Required) The name of the restore testing plan.

* `protected_resource_type` - (Required) The type of the protected resource.

* `iam_role_arn` - (Required) The ARN of the IAM role.

* `protected_resource_conditions` - (Required) The conditions for the protected resource.

* `restore_metadata_overrides` - (Optional) Override certain restore metadata keys. See the complete list of [restore testing inferred metadata](https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing-inferred-metadata.html) .

The `protected_resource_conditions` block supports the following arguments:

* `string_equals` - (Optional) The list of string equals conditions for resource tags. Filters the values of your tagged resources for only those resources that you tagged with the same value. Also called "exact matching.". See [the structure for details](#keyvalues)

* `string_not_equals` - (Optional) The list of string not equals conditions for resource tags. Filters the values of your tagged resources for only those resources that you tagged that do not have the same value. Also called "negated matching.". See [the structure for details](#keyvalues)

### KeyValues

* `key` - The Tag name, must start with one of the following prefixes: [aws:ResourceTag/] with a Minimum length of 1. Maximum length of 128, and can contain characters that are letters, white space, and numbers that can be represented in UTF-8 and the following characters: `+ - = . _ : /`.
* `value` - The value of the Tag. Maximum length of 256.

## Timeouts

The following timeouts are available for this resource:

* `create` - (Default `5m`)
* `update` - (Default `5m`)
* `delete` - (Default `5m`)

## Import

To import an existing backup restore testing selection, use the following `import` block:

```
import {
  to = aws_backup_restore_testing_selection.example
  id = "my_testing_selection:my_testing_plan"
}
```

Using `terraform import`, import Backup Restore Testing Selection using the `name:restore_testing_plan_name`. For example:

```console
% terraform import aws_backup_restore_testing_selection.example restore_testing_selection_12345678:restore_testing_plan_12345678
```
