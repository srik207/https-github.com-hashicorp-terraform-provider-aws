// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package batch

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/private/protocol/json/jsonutil"
	"github.com/aws/aws-sdk-go/service/batch"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/structure"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

const (
	jobDefinitionStatusInactive = "INACTIVE"
	jobDefinitionStatusActive   = "ACTIVE"
)

// @SDKResource("aws_batch_job_definition", name="Job Definition")
// @Tags(identifierAttribute="arn")
func ResourceJobDefinition() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceJobDefinitionCreate,
		ReadWithoutTimeout:   resourceJobDefinitionRead,
		UpdateWithoutTimeout: resourceJobDefinitionUpdate,
		DeleteWithoutTimeout: resourceJobDefinitionDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"arn_prefix": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"container_properties": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"eks_properties", "node_properties"},
				StateFunc: func(v interface{}) string {
					json, _ := structure.NormalizeJsonString(v)
					return json
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					equal, _ := EquivalentContainerPropertiesJSON(old, new)

					return equal
				},
				ValidateFunc: validJobContainerProperties,
			},

			"deregister_on_new_revision": {
				Type:     schema.TypeBool,
				Default:  true,
				Optional: true,
			},

			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validName,
			},
			"node_properties": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"container_properties", "eks_properties"},
				StateFunc: func(v interface{}) string {
					json, _ := structure.NormalizeJsonString(v)
					return json
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					equal, _ := EquivalentNodePropertiesJSON(old, new)
					return equal
				},
				ValidateFunc: validJobNodeProperties,
			},
			"eks_properties": {
				Type:          schema.TypeList,
				MaxItems:      1,
				Optional:      true,
				ConflictsWith: []string{"container_properties", "node_properties"},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"pod_properties": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"containers": {
										Type:     schema.TypeList,
										Required: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"args": {
													Type:     schema.TypeList,
													Optional: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
												"command": {
													Type:     schema.TypeList,
													Optional: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
												"env": {
													Type:     schema.TypeSet,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"name": {
																Type:     schema.TypeString,
																Required: true,
															},
															"value": {
																Type:     schema.TypeString,
																Required: true,
															},
														},
													},
												},
												"image": {
													Type:     schema.TypeString,
													Required: true,
												},
												"image_pull_policy": {
													Type:     schema.TypeString,
													Optional: true,
													ValidateFunc: validation.StringInSlice([]string{
														"Always",
														"IfNotPresent",
														"Never",
													}, false),
												},
												"name": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"resources": {
													Type:     schema.TypeList,
													Optional: true,
													MaxItems: 1,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"limits": {
																Type:     schema.TypeMap,
																Optional: true,
																Elem:     &schema.Schema{Type: schema.TypeString},
															},
															"requests": {
																Type:     schema.TypeMap,
																Optional: true,
																Elem:     &schema.Schema{Type: schema.TypeString},
															},
														},
													},
												},
												"security_context": {
													Type:     schema.TypeList,
													Optional: true,
													MaxItems: 1,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"privileged": {
																Type:     schema.TypeBool,
																Optional: true,
															},
															"read_only_root_file_system": {
																Type:     schema.TypeBool,
																Optional: true,
															},
															"run_as_group": {
																Type:     schema.TypeInt,
																Optional: true,
															},
															"run_as_non_root": {
																Type:     schema.TypeBool,
																Optional: true,
															},
															"run_as_user": {
																Type:     schema.TypeInt,
																Optional: true,
															},
														},
													},
												},
												"volume_mounts": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"mount_path": {
																Type:     schema.TypeString,
																Required: true,
															},
															"name": {
																Type:     schema.TypeString,
																Required: true,
															},
															"read_only": {
																Type:     schema.TypeBool,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
									"dns_policy": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validation.StringInSlice([]string{"Default", "ClusterFirst", "ClusterFirstWithHostNet"}, false),
									},
									"host_network": {
										Type:     schema.TypeBool,
										Optional: true,
									},
									"metadata": {
										Type:     schema.TypeList,
										Optional: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"labels": {
													Type:     schema.TypeMap,
													Optional: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
											},
										},
									},
									"service_account_name": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"volumes": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"empty_dir": {
													Type:     schema.TypeList,
													MaxItems: 1,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"medium": {
																Type:     schema.TypeString,
																Required: true,
															},
															"size_limit": {
																Type:     schema.TypeString,
																Required: true,
															},
														},
													},
												},
												"host_path": {
													Type:     schema.TypeList,
													Optional: true,
													MaxItems: 1,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"path": {
																Type:     schema.TypeString,
																Required: true,
															},
														},
													},
												},
												"name": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"secret": {
													Type:     schema.TypeSet,
													Optional: true,
													MaxItems: 1,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"secret_name": {
																Type:     schema.TypeString,
																Required: true,
															},
															"optional": {
																Type:     schema.TypeBool,
																Optional: true,
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"parameters": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// If the job runs on Amazon EKS resources, then you must not specify platformCapabilities.
			"platform_capabilities": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice(batch.PlatformCapability_Values(), false),
				},
			},

			// If the job runs on Amazon EKS resources, then you must not specify propagateTags.
			"propagate_tags": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			"retry_strategy": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attempts": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntBetween(1, 10),
						},

						"evaluate_on_exit": {
							Type:     schema.TypeList,
							Optional: true,
							MinItems: 0,
							MaxItems: 5,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"action": {
										Type:     schema.TypeString,
										Required: true,
										StateFunc: func(v interface{}) string {
											return strings.ToLower(v.(string))
										},
										ValidateFunc: validation.StringInSlice(batch.RetryAction_Values(), true),
									},

									"on_exit_code": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateFunc: validation.All(
											validation.StringLenBetween(1, 512),
											validation.StringMatch(regexache.MustCompile(`^[0-9]*\*?$`), "must contain only numbers, and can optionally end with an asterisk"),
										),
									},

									"on_reason": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateFunc: validation.All(
											validation.StringLenBetween(1, 512),
											validation.StringMatch(regexache.MustCompile(`^[0-9A-Za-z.:\s]*\*?$`), "must contain letters, numbers, periods, colons, and white space, and can optionally end with an asterisk"),
										),
									},

									"on_status_reason": {
										Type:     schema.TypeString,
										Optional: true,
										ValidateFunc: validation.All(
											validation.StringLenBetween(1, 512),
											validation.StringMatch(regexache.MustCompile(`^[0-9A-Za-z.:\s]*\*?$`), "must contain letters, numbers, periods, colons, and white space, and can optionally end with an asterisk"),
										),
									},
								},
							},
						},
					},
				},
			},

			"revision": {
				Type:     schema.TypeInt,
				Computed: true,
			},

			"scheduling_priority": {
				Type:     schema.TypeInt,
				Optional: true,
			},

			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),

			"timeout": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attempt_duration_seconds": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntAtLeast(60),
						},
					},
				},
			},

			"type": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice(batch.JobDefinitionType_Values(), true),
			},
		},

		CustomizeDiff: verify.SetTagsDiff,
	}
}

func resourceJobDefinitionCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BatchConn(ctx)

	name := d.Get("name").(string)
	jobDefinitionType := d.Get("type").(string)
	input := &batch.RegisterJobDefinitionInput{
		JobDefinitionName: aws.String(name),
		PropagateTags:     aws.Bool(d.Get("propagate_tags").(bool)),
		Tags:              getTagsIn(ctx),
		Type:              aws.String(jobDefinitionType),
	}

	if jobDefinitionType == batch.JobDefinitionTypeContainer {
		if v, ok := d.GetOk("node_properties"); ok && v != nil {
			return sdkdiag.AppendErrorf(diags, "No `node_properties` can be specified when `type` is %q", jobDefinitionType)
		}

		if v, ok := d.GetOk("container_properties"); ok {
			props, err := expandJobContainerProperties(v.(string))
			if err != nil {
				return sdkdiag.AppendErrorf(diags, "creating Batch Job Definition (%s): %s", name, err)
			}

			if aws.StringValue(input.Type) == batch.JobDefinitionTypeContainer {
				removeEmptyEnvironmentVariables(&diags, props.Environment, cty.GetAttrPath("container_properties"))
				input.ContainerProperties = props
			}
		}
		if v, ok := d.GetOk("eks_properties"); ok && len(v.([]interface{})) > 0 {
			eksProps := v.([]interface{})[0].(map[string]interface{})
			if podProps, ok := eksProps["pod_properties"].([]interface{}); ok && len(podProps) > 0 {
				if aws.StringValue(input.Type) == batch.JobDefinitionTypeContainer {
					props, err := expandEksPodProperties(podProps[0].(map[string]interface{}))
					if err != nil {
						return sdkdiag.AppendErrorf(diags, "creating Batch Job Definition (%s): %s", name, err)
					}
					input.EksProperties = &batch.EksProperties{
						PodProperties: props,
					}
				}
			}
		}
	}

	if jobDefinitionType == batch.JobDefinitionTypeMultinode {
		if v, ok := d.GetOk("container_properties"); ok && v != nil {
			return sdkdiag.AppendErrorf(diags, "No `container_properties` can be specified when `type` is %q", jobDefinitionType)
		}
		if v, ok := d.GetOk("eks_properties"); ok && v != nil {
			return sdkdiag.AppendErrorf(diags, "No `eks_properties` can be specified when `type` is %q", jobDefinitionType)
		}

		if v, ok := d.GetOk("node_properties"); ok {
			props, err := expandJobNodeProperties(v.(string))
			if err != nil {
				return sdkdiag.AppendErrorf(diags, "creating Batch Job Definition (%s): %s", name, err)
			}

			for _, node := range props.NodeRangeProperties {
				removeEmptyEnvironmentVariables(&diags, node.Container.Environment, cty.GetAttrPath("node_properties"))
			}
			input.NodeProperties = props
		}
	}

	if v, ok := d.GetOk("parameters"); ok {
		input.Parameters = expandJobDefinitionParameters(v.(map[string]interface{}))
	}

	if v, ok := d.GetOk("platform_capabilities"); ok && v.(*schema.Set).Len() > 0 {
		input.PlatformCapabilities = flex.ExpandStringSet(v.(*schema.Set))
	}

	if v, ok := d.GetOk("retry_strategy"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		input.RetryStrategy = expandRetryStrategy(v.([]interface{})[0].(map[string]interface{}))
	}

	if v, ok := d.GetOk("timeout"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		input.Timeout = expandJobTimeout(v.([]interface{})[0].(map[string]interface{}))
	}

	if v, ok := d.GetOk("scheduling_priority"); ok {
		input.SchedulingPriority = aws.Int64(int64(v.(int)))
	}

	output, err := conn.RegisterJobDefinitionWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Batch Job Definition (%s): %s", name, err)
	}

	d.SetId(aws.StringValue(output.JobDefinitionArn))

	return append(diags, resourceJobDefinitionRead(ctx, d, meta)...)
}

func resourceJobDefinitionRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BatchConn(ctx)

	jobDefinition, err := FindJobDefinitionByARN(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] Batch Job Definition (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Batch Job Definition (%s): %s", d.Id(), err)
	}

	d.Set("arn", jobDefinition.JobDefinitionArn)
	d.Set("arn_prefix", strings.TrimSuffix(*jobDefinition.JobDefinitionArn, fmt.Sprintf(":%d", *jobDefinition.Revision)))

	containerProperties, err := flattenContainerProperties(jobDefinition.ContainerProperties)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "converting Batch Container Properties to JSON: %s", err)
	}

	if err := d.Set("container_properties", containerProperties); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting container_properties: %s", err)
	}

	d.Set("deregister_on_new_revision", d.Get("deregister_on_new_revision").(bool))

	nodeProperties, err := flattenNodeProperties(jobDefinition.NodeProperties)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "converting Batch Node Properties to JSON: %s", err)
	}

	if err := d.Set("node_properties", nodeProperties); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting node_properties: %s", err)
	}

	if err := d.Set("eks_properties", flattenEksProperties(jobDefinition.EksProperties)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting eks_properties: %s", err)
	}

	d.Set("name", jobDefinition.JobDefinitionName)
	d.Set("parameters", aws.StringValueMap(jobDefinition.Parameters))
	d.Set("platform_capabilities", aws.StringValueSlice(jobDefinition.PlatformCapabilities))
	d.Set("propagate_tags", jobDefinition.PropagateTags)

	if jobDefinition.RetryStrategy != nil {
		if err := d.Set("retry_strategy", []interface{}{flattenRetryStrategy(jobDefinition.RetryStrategy)}); err != nil {
			return sdkdiag.AppendErrorf(diags, "setting retry_strategy: %s", err)
		}
	} else {
		d.Set("retry_strategy", nil)
	}

	setTagsOut(ctx, jobDefinition.Tags)

	if jobDefinition.Timeout != nil {
		if err := d.Set("timeout", []interface{}{flattenJobTimeout(jobDefinition.Timeout)}); err != nil {
			return sdkdiag.AppendErrorf(diags, "setting timeout: %s", err)
		}
	} else {
		d.Set("timeout", nil)
	}

	d.Set("revision", jobDefinition.Revision)
	d.Set("type", jobDefinition.Type)
	d.Set("scheduling_priority", jobDefinition.SchedulingPriority)

	return diags
}

func resourceJobDefinitionUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BatchConn(ctx)

	if d.HasChangesExcept("tags", "tags_all") {
		name := d.Get("name").(string)
		input := &batch.RegisterJobDefinitionInput{
			JobDefinitionName: aws.String(name),
			Type:              aws.String(d.Get("type").(string)),
		}

		if v, ok := d.GetOk("container_properties"); ok {
			props, err := expandJobContainerProperties(v.(string))
			if err != nil {
				return sdkdiag.AppendErrorf(diags, "updating Batch Job Definition (%s): %s", name, err)
			}

			if aws.StringValue(input.Type) == batch.JobDefinitionTypeContainer {
				removeEmptyEnvironmentVariables(&diags, props.Environment, cty.GetAttrPath("container_properties"))
				input.ContainerProperties = props
			}
		}

		if v, ok := d.GetOk("node_properties"); ok {
			props, err := expandJobNodeProperties(v.(string))
			if err != nil {
				return sdkdiag.AppendErrorf(diags, "updating Batch Job Definition (%s): %s", name, err)
			}

			for _, node := range props.NodeRangeProperties {
				removeEmptyEnvironmentVariables(&diags, node.Container.Environment, cty.GetAttrPath("node_properties"))
			}
			input.NodeProperties = props
		}

		if v, ok := d.GetOk("eks_properties"); ok {
			eksProps := v.([]interface{})[0].(map[string]interface{})
			if podProps, ok := eksProps["pod_properties"].([]interface{}); ok && len(podProps) > 0 {
				props, err := expandEksPodProperties(podProps[0].(map[string]interface{}))
				if err != nil {
					return sdkdiag.AppendErrorf(diags, "updating Batch Job Definition (%s): %s", name, err)
				}
				input.EksProperties = &batch.EksProperties{
					PodProperties: props,
				}
			}
		}

		if v, ok := d.GetOk("propagate_tags"); ok {
			input.PropagateTags = aws.Bool(v.(bool))
		}

		if v, ok := d.GetOk("parameters"); ok {
			input.Parameters = expandJobDefinitionParameters(v.(map[string]interface{}))
		}

		if v, ok := d.GetOk("platform_capabilities"); ok && v.(*schema.Set).Len() > 0 {
			input.PlatformCapabilities = flex.ExpandStringSet(v.(*schema.Set))
		}

		if v, ok := d.GetOk("scheduling_priority"); ok {
			input.SchedulingPriority = aws.Int64(int64(v.(int)))
		}

		if v, ok := d.GetOk("retry_strategy"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
			input.RetryStrategy = expandRetryStrategy(v.([]interface{})[0].(map[string]interface{}))
		}

		if v, ok := d.GetOk("timeout"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
			input.Timeout = expandJobTimeout(v.([]interface{})[0].(map[string]interface{}))
		}

		jd, err := conn.RegisterJobDefinitionWithContext(ctx, input)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating Batch Job Definition (%s): %s", name, err)
		}

		// arn contains revision which is used in the Read call
		currentARN := d.Get("arn").(string)
		d.SetId(aws.StringValue(jd.JobDefinitionArn))
		d.Set("revision", jd.Revision)

		if v := d.Get("deregister_on_new_revision"); v == true {
			log.Printf("[DEBUG] Deleting Previous Batch Job Definition: %s", currentARN)
			_, err := conn.DeregisterJobDefinitionWithContext(ctx, &batch.DeregisterJobDefinitionInput{
				JobDefinition: aws.String(currentARN),
			})

			if err != nil {
				return sdkdiag.AppendErrorf(diags, "deleting Batch Job Definition (%s): %s", currentARN, err)
			}
		}
	}

	return append(diags, resourceJobDefinitionRead(ctx, d, meta)...)
}

func resourceJobDefinitionDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BatchConn(ctx)

	name := d.Get("name").(string)
	jds, err := ListActiveJobDefinitionByName(ctx, conn, name)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Batch Job Definitions (%s): %s", name, err)
	}

	for i := range jds {
		arn := aws.StringValue(jds[i].JobDefinitionArn)
		log.Printf("[DEBUG] Deleting Batch Job Definition: %s", arn)
		_, err := conn.DeregisterJobDefinitionWithContext(ctx, &batch.DeregisterJobDefinitionInput{
			JobDefinition: aws.String(arn),
		})

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "deleting Batch Job Definition (%s): %s", arn, err)
		}
	}

	return diags
}

func FindJobDefinitionByARN(ctx context.Context, conn *batch.Batch, arn string) (*batch.JobDefinition, error) {
	input := &batch.DescribeJobDefinitionsInput{
		JobDefinitions: aws.StringSlice([]string{arn}),
	}

	output, err := findJobDefinition(ctx, conn, input)

	if err != nil {
		return nil, err
	}

	if status := aws.StringValue(output.Status); status == jobDefinitionStatusInactive {
		return nil, &retry.NotFoundError{
			Message:     status,
			LastRequest: input,
		}
	}

	return output, nil
}

func findJobDefinition(ctx context.Context, conn *batch.Batch, input *batch.DescribeJobDefinitionsInput) (*batch.JobDefinition, error) {
	output, err := conn.DescribeJobDefinitionsWithContext(ctx, input)

	if err != nil {
		return nil, err
	}

	if output == nil || len(output.JobDefinitions) == 0 || output.JobDefinitions[0] == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	if count := len(output.JobDefinitions); count > 1 {
		return nil, tfresource.NewTooManyResultsError(count, input)
	}

	return output.JobDefinitions[0], nil
}

func ListActiveJobDefinitionByName(ctx context.Context, conn *batch.Batch, name string) ([]*batch.JobDefinition, error) {
	input := &batch.DescribeJobDefinitionsInput{
		JobDefinitionName: aws.String(name),
		Status:            aws.String(jobDefinitionStatusActive),
	}

	output, err := conn.DescribeJobDefinitionsWithContext(ctx, input)

	if err != nil {
		return nil, err
	}

	return output.JobDefinitions, nil
}

func validJobContainerProperties(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	_, err := expandJobContainerProperties(value)
	if err != nil {
		errors = append(errors, fmt.Errorf("AWS Batch Job container_properties is invalid: %s", err))
	}
	return
}

func expandJobContainerProperties(rawProps string) (*batch.ContainerProperties, error) {
	var props *batch.ContainerProperties

	err := json.Unmarshal([]byte(rawProps), &props)
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %s", err)
	}

	return props, nil
}

// Convert batch.ContainerProperties object into its JSON representation
func flattenContainerProperties(containerProperties *batch.ContainerProperties) (string, error) {
	b, err := jsonutil.BuildJSON(containerProperties)

	if err != nil {
		return "", err
	}

	return string(b), nil
}

func validJobNodeProperties(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	_, err := expandJobNodeProperties(value)
	if err != nil {
		errors = append(errors, fmt.Errorf("AWS Batch Job node_properties is invalid: %s", err))
	}
	return
}

func expandJobNodeProperties(rawProps string) (*batch.NodeProperties, error) {
	var props *batch.NodeProperties

	err := json.Unmarshal([]byte(rawProps), &props)
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %s", err)
	}

	return props, nil
}

// Convert batch.NodeProperties object into its JSON representation
func flattenNodeProperties(nodeProperties *batch.NodeProperties) (string, error) {
	b, err := jsonutil.BuildJSON(nodeProperties)

	if err != nil {
		return "", err
	}

	return string(b), nil
}

func expandJobDefinitionParameters(params map[string]interface{}) map[string]*string {
	var jobParams = make(map[string]*string)
	for k, v := range params {
		jobParams[k] = aws.String(v.(string))
	}

	return jobParams
}

func expandRetryStrategy(tfMap map[string]interface{}) *batch.RetryStrategy {
	if tfMap == nil {
		return nil
	}

	apiObject := &batch.RetryStrategy{}

	if v, ok := tfMap["attempts"].(int); ok && v != 0 {
		apiObject.Attempts = aws.Int64(int64(v))
	}

	if v, ok := tfMap["evaluate_on_exit"].([]interface{}); ok && len(v) > 0 {
		apiObject.EvaluateOnExit = expandEvaluateOnExits(v)
	}

	return apiObject
}

func expandEvaluateOnExit(tfMap map[string]interface{}) *batch.EvaluateOnExit {
	if tfMap == nil {
		return nil
	}

	apiObject := &batch.EvaluateOnExit{}

	if v, ok := tfMap["action"].(string); ok && v != "" {
		apiObject.Action = aws.String(v)
	}

	if v, ok := tfMap["on_exit_code"].(string); ok && v != "" {
		apiObject.OnExitCode = aws.String(v)
	}

	if v, ok := tfMap["on_reason"].(string); ok && v != "" {
		apiObject.OnReason = aws.String(v)
	}

	if v, ok := tfMap["on_status_reason"].(string); ok && v != "" {
		apiObject.OnStatusReason = aws.String(v)
	}

	return apiObject
}

func expandEvaluateOnExits(tfList []interface{}) []*batch.EvaluateOnExit {
	if len(tfList) == 0 {
		return nil
	}

	var apiObjects []*batch.EvaluateOnExit

	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})

		if !ok {
			continue
		}

		apiObject := expandEvaluateOnExit(tfMap)

		if apiObject == nil {
			continue
		}

		apiObjects = append(apiObjects, apiObject)
	}

	return apiObjects
}

func flattenRetryStrategy(apiObject *batch.RetryStrategy) map[string]interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if v := apiObject.Attempts; v != nil {
		tfMap["attempts"] = aws.Int64Value(v)
	}

	if v := apiObject.EvaluateOnExit; v != nil {
		tfMap["evaluate_on_exit"] = flattenEvaluateOnExits(v)
	}

	return tfMap
}

func flattenEvaluateOnExit(apiObject *batch.EvaluateOnExit) map[string]interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if v := apiObject.Action; v != nil {
		tfMap["action"] = aws.StringValue(v)
	}

	if v := apiObject.OnExitCode; v != nil {
		tfMap["on_exit_code"] = aws.StringValue(v)
	}

	if v := apiObject.OnReason; v != nil {
		tfMap["on_reason"] = aws.StringValue(v)
	}

	if v := apiObject.OnStatusReason; v != nil {
		tfMap["on_status_reason"] = aws.StringValue(v)
	}

	return tfMap
}

func flattenEvaluateOnExits(apiObjects []*batch.EvaluateOnExit) []interface{} {
	if len(apiObjects) == 0 {
		return nil
	}

	var tfList []interface{}

	for _, apiObject := range apiObjects {
		if apiObject == nil {
			continue
		}

		tfList = append(tfList, flattenEvaluateOnExit(apiObject))
	}

	return tfList
}

func expandJobTimeout(tfMap map[string]interface{}) *batch.JobTimeout {
	if tfMap == nil {
		return nil
	}

	apiObject := &batch.JobTimeout{}

	if v, ok := tfMap["attempt_duration_seconds"].(int); ok && v != 0 {
		apiObject.AttemptDurationSeconds = aws.Int64(int64(v))
	}

	return apiObject
}

func flattenJobTimeout(apiObject *batch.JobTimeout) map[string]interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if v := apiObject.AttemptDurationSeconds; v != nil {
		tfMap["attempt_duration_seconds"] = aws.Int64Value(v)
	}

	return tfMap
}

func removeEmptyEnvironmentVariables(diags *diag.Diagnostics, environment []*batch.KeyValuePair, attributePath cty.Path) {
	for _, env := range environment {
		if aws.StringValue(env.Value) == "" {
			*diags = append(*diags, errs.NewAttributeWarningDiagnostic(
				attributePath,
				"Ignoring environment variable",
				fmt.Sprintf("The environment variable %q has an empty value, which is ignored by the Batch service", aws.StringValue(env.Name))),
			)
		}
	}
}
