// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	// "github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/id"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/structure"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	fwtypes "github.com/hashicorp/terraform-provider-aws/internal/framework/types"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

const (
	roleNameMaxLen       = 64
	roleNamePrefixMaxLen = roleNameMaxLen - id.UniqueIDSuffixLength
	ResNameIamRole       = "IAM Role"
)

// @FrameworkResource(name="Role")
// @Tags(identifierAttribute="id")
func newResourceRole(_ context.Context) (resource.ResourceWithConfigure, error) {
	r := &resourceIamRole{}
	r.SetMigratedFromPluginSDK(true)

	return r, nil
}

type resourceIamRole struct {
	framework.ResourceWithConfigure
}

func (r *resourceIamRole) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = "aws_iam_role"
}

func (r *resourceIamRole) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"arn": schema.StringAttribute{
				CustomType: fwtypes.ARNType,
				Computed:   true,
				Optional:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			// TODO: should this be this?
			// "github.com/hashicorp/terraform-provider-aws/internal/framework"
			//framework.IDAttribute()
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"assume_role_policy": schema.StringAttribute{
				Required:   true,
				CustomType: fwtypes.IAMPolicyType,
				// Validators: []validator.String{
				// // TODO: json validator
				// },
				// TODO: finish this, it get complicated
			},
			"create_date": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(""),
				Validators: []validator.String{
					stringvalidator.LengthBetween(0, 1000),
					// TODO: figure this out later for both validators
					// stringvalidator.RegexMatches(
					// regexache.MustCompile(
					// `[\p{L}\p{M}\p{Z}\p{S}\p{N}\p{P}]*`),
					// `must satisfy regular expression pattern: [\p{L}\p{M}\p{Z}\p{S}\p{N}\p{P}]*)`,
					// ),
				},
				// TODO: do something here
			},
			"force_detach_policies": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				// PlanModifiers: []planmodifier.Bool{
				// boolplanmodifier.UseStateForUnknown(),
				// },
			},
			"inline_policies": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			// "managed_policy_arns": schema.SetAttribute{
			// Computed:    true,
			// Optional:    true,
			// ElementType: types.StringType,
			// // TODO: set validator for arn
			// // TODO: validate all elements of set are valid arns
			// // how to do this with helper lib terraform-plugin-framework-validators
			// },
			"max_session_duration": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(3600),
				Validators: []validator.Int64{
					int64validator.Between(3600, 43200),
				},
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown(),
				},
				// Default: stringdefault.StaticString(""),
				Validators: []validator.String{
					stringvalidator.LengthAtMost(roleNameMaxLen),
					// TODO: uncomment when ready
					// stringvalidator.ConflictsWith(
					// path.MatchRelative().AtParent().AtName("name_prefix"),
					// ),
				},
			},
			"name_prefix": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtMost(roleNamePrefixMaxLen),
					stringvalidator.ConflictsWith(
						path.MatchRelative().AtParent().AtName("name"),
					),
				},
			},
			"path": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("/"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					// TODO: can I do this and remove setting in Update/read?
					stringplanmodifier.UseStateForUnknown(),
				},
				// Default: stringdefault.StaticString("/"),
				Validators: []validator.String{
					stringvalidator.LengthBetween(0, 512),
				},
			},
			"permissions_boundary": schema.StringAttribute{
				CustomType: fwtypes.ARNType,
				Optional:   true,
				// Computed:   true,
				// Default:    stringdefault.StaticString(""),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			// "unique_id": schema.StringAttribute{
			// Computed: true,
			// },
			names.AttrTags:    tftags.TagsAttribute(),
			names.AttrTagsAll: tftags.TagsAttributeComputedOnly(),
		},
	}
}

type resourceIamRoleData struct {
	ARN                 fwtypes.ARN       `tfsdk:"arn"`
	AssumeRolePolicy    fwtypes.IAMPolicy `tfsdk:"assume_role_policy"`
	CreateDate          types.String      `tfsdk:"create_date"`
	ID                  types.String      `tfsdk:"id"`
	Description         types.String      `tfsdk:"description"`
	ForceDetachPolicies types.Bool        `tfsdk:"force_detach_policies"`
	MaxSessionDuration  types.Int64       `tfsdk:"max_session_duration"`
	Name                types.String      `tfsdk:"name"`
	NamePrefix          types.String      `tfsdk:"name_prefix"`
	Path                types.String      `tfsdk:"path"`
	PermissionsBoundary fwtypes.ARN       `tfsdk:"permissions_boundary"`
	Tags                types.Map         `tfsdk:"tags"`
	TagsAll             types.Map         `tfsdk:"tags_all"`
	InlinePolicies      types.Map         `tfsdk:"inline_policies"`

	// TODO: still have to think this one out
	// ManagedPolicyArns   types.Set    `tfsdk:"managed_policy_arns"`
	// UniqueId            types.String `tfsdk:"unique_id"`
}

func (r resourceIamRole) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	fmt.Println("Hitting top of Create")
	conn := r.Meta().IAMConn(ctx)

	var plan resourceIamRoleData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	assumeRolePolicy, err := structure.NormalizeJsonString(plan.AssumeRolePolicy.ValueString())

	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.IAM, create.ErrActionCreating, ResNameIamRole, plan.AssumeRolePolicy.String(), nil),
			errors.New(fmt.Sprintf("assume_role_policy (%s) is invalid JSON: %s", assumeRolePolicy, err)).Error(),
		)
		return
	}

	name := create.Name(plan.Name.ValueString(), plan.NamePrefix.ValueString())

	input := &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(assumeRolePolicy),
		Path:                     aws.String(plan.Path.ValueString()),
		RoleName:                 aws.String(name),
		Tags:                     getTagsIn(ctx),
	}

	if !plan.Description.IsNull() {
		input.Description = aws.String(plan.Description.ValueString())
	}

	if !plan.MaxSessionDuration.IsNull() {
		input.MaxSessionDuration = aws.Int64(plan.MaxSessionDuration.ValueInt64())
	}

	if !plan.PermissionsBoundary.IsNull() {
		input.PermissionsBoundary = aws.String(plan.PermissionsBoundary.ValueString())
	}

	// TODO: uncomment this
	output, err := retryCreateRole(ctx, conn, input)

	// TODO: So this needs tags... do we need on resourceIamRoleData?
	// if input.Tags != nil && errs.IsUnsupportedOperationInPartitionError(conn.PartitionID, err) {
	// input.Tags = nil

	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.IAM, create.ErrActionCreating, ResNameIamRole, name, nil),
			err.Error(),
		)
		return
	}

	roleName := aws.StringValue(output.Role.RoleName)

	if !plan.InlinePolicies.IsNull() && !plan.InlinePolicies.IsUnknown() {
		fmt.Println("Found Inline Policies!")
		inline_policies_map := make(map[string]string)
		plan.InlinePolicies.ElementsAs(ctx, &inline_policies_map, false)
		// v, _ := plan.InlinePolicies.ToMapValue(ctx)
		fmt.Println(fmt.Sprintf("len inline_policies_map: %v", len(inline_policies_map)))
		// fmt.Println(fmt.Sprintf("inline_policies_map: %+v", inline_policies_map))
		policies := expandRoleInlinePolicies(roleName, inline_policies_map)
		// fmt.Println(fmt.Sprintf("policies: %+v", policies))
		if err := r.addRoleInlinePolicies(ctx, policies); err != nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.IAM, create.ErrActionCreating, ResNameIamRole, name, nil),
				err.Error(),
			)
			return
		}
	}

	// if !plan.ManagedPolicyArns.IsNull() && !plan.ManagedPolicyArns.IsUnknown() {
	// managedPolicies := flex.ExpandFrameworkStringSet(ctx, plan.ManagedPolicyArns)
	// if err := r.addRoleManagedPolicies(ctx, roleName, managedPolicies); err != nil {
	// resp.Diagnostics.AddError(
	// create.ProblemStandardMessage(names.IAM, create.ErrActionCreating, ResNameIamRole, name, nil),
	// err.Error(),
	// )
	// return
	// }
	// }

	// For partitions not supporting tag-on-create, attempt tag after create.
	if tags := getTagsIn(ctx); input.Tags == nil && len(tags) > 0 {
		err := roleCreateTags(ctx, conn, name, tags)

		// TODO: read errors or something
		// If default tags only, continue. Otherwise, error.
		// if v, ok := d.GetOk(names.AttrTags); (!ok || len(v.(map[string]interface{})) == 0) && errs.IsUnsupportedOperationInPartitionError(conn.PartitionID, err) {
		// return append(diags, resourceRoleRead(ctx, d, meta)...)
		// }

		if err != nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.IAM, create.ErrActionCreating, fmt.Sprintf("%s tags", ResNameIamRole), name, nil),
				err.Error(),
			)
			return
		}
	}

	// TODO: do I have to do this? should look at other resources
	plan.ARN = fwtypes.ARNValue(*output.Role.Arn)
	plan.CreateDate = flex.StringValueToFramework(ctx, output.Role.CreateDate.Format(time.RFC3339))
	plan.ID = flex.StringToFramework(ctx, output.Role.RoleName)
	plan.Name = flex.StringToFramework(ctx, output.Role.RoleName)
	plan.NamePrefix = flex.StringToFramework(ctx, create.NamePrefixFromName(aws.StringValue(output.Role.RoleName)))

	// last steps?
	// TODO: do we need something?this?
	// state.refreshFromOutput(ctx, out)
	// fmt.Println(plan.ARN)
	// fmt.Println(plan.ID)
	// fmt.Println(plan.Name)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	fmt.Println("Bottom of Create")
}

func (r resourceIamRole) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	conn := r.Meta().IAMConn(ctx)

	var state resourceIamRoleData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasInline := false
	if !state.InlinePolicies.IsNull() && !state.InlinePolicies.IsUnknown() {
		hasInline = true
	}

	// hasManaged := false
	// if !state.ManagedPolicyArns.IsNull() && !state.ManagedPolicyArns.IsUnknown() {
	// hasManaged = true
	// }

	// err := DeleteRole(ctx, conn, state.Name.ValueString(), state.ForceDetachPolicies.ValueBool(), hasInline, hasManaged)
	// TODO: should name be ID here?
	err := DeleteRole(ctx, conn, state.Name.ValueString(), state.ForceDetachPolicies.ValueBool(), hasInline, false)

	if err != nil {
		// TODO: do something like this to skip deletes on roles that are gone?
		// if err.IsA[*awstypes.ResourceNotFoundException](err) {
		// return
		// }
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.IAM, create.ErrActionDeleting, state.Name.String(), state.ARN.String(), err),
			err.Error(),
		)
		return
	}
}

func (r *resourceIamRole) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	fmt.Println("Top of Import")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func (r *resourceIamRole) ModifyPlan(ctx context.Context, request resource.ModifyPlanRequest, response *resource.ModifyPlanResponse) {
	r.SetTagsAll(ctx, request, response)
}

func (r resourceIamRole) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	fmt.Println("Top of Read")
	conn := r.Meta().IAMConn(ctx)

	var state resourceIamRoleData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	//NOTE: Have to always set this to true? Else not sure what to do
	outputRaw, err := tfresource.RetryWhenNewResourceNotFound(ctx, propagationTimeout, func() (interface{}, error) {
		return FindRoleByName(ctx, conn, state.ID.ValueString())
	}, true)

	// NOTE: Same issue here, I left old conditional here as example, not sure what else can/should be done
	// if !d.IsNewResource() && tfresource.NotFound(err) {
	if tfresource.NotFound(err) {
		// log.Printf("[WARN] IAM Role (%s) not found, removing from state", d.Id())
		// d.SetId("")
		// return diags
		resp.State.RemoveResource(ctx)
		return
	}

	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.IAM, create.ErrActionSetting, state.Name.String(), state.ARN.String(), err),
			err.Error(),
		)
		return
	}

	role := outputRaw.(*iam.Role)

	// occasionally, immediately after a role is created, AWS will give an ARN like AROAQ7SSZBKHREXAMPLE (unique ID)
	if role, err = waitRoleARNIsNotUniqueID(ctx, conn, state.ARN.ValueString(), role); err != nil {
		// TODO: have to update this error
		// return sdkdiag.AppendErrorf(diags, "reading IAM Role (%s): waiting for valid ARN: %s", d.Id(), err)
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.IAM, create.ErrActionSetting, state.Name.String(), state.ARN.String(), err),
			err.Error(),
		)
		return
	}

	state.ARN = fwtypes.ARNValue(*role.Arn)
	state.CreateDate = flex.StringValueToFramework(ctx, role.CreateDate.Format(time.RFC3339))
	state.Path = flex.StringToFramework(ctx, role.Path)
	state.Name = flex.StringToFramework(ctx, role.RoleName)
	state.ID = flex.StringToFramework(ctx, role.RoleName)
	state.Description = flex.StringToFramework(ctx, role.Description)
	state.NamePrefix = flex.StringToFramework(ctx, create.NamePrefixFromName(aws.StringValue(role.RoleName)))
	state.MaxSessionDuration = flex.Int64ToFramework(ctx, role.MaxSessionDuration)

	if state.ForceDetachPolicies.IsNull() {
		// TODO: better way to do this that is more framework friendly?
		temp := false
		state.ForceDetachPolicies = flex.BoolToFramework(ctx, &temp)
	}

	if role.PermissionsBoundary != nil {
		state.PermissionsBoundary = fwtypes.ARNValue(*role.PermissionsBoundary.PermissionsBoundaryArn)
	} else {
		state.PermissionsBoundary = fwtypes.ARNNull()
	}

	// d.Set("unique_id", role.RoleId)

	assumeRolePolicy, err := url.QueryUnescape(aws.StringValue(role.AssumeRolePolicyDocument))
	if err != nil {
		// TODO: I don't this this is right error, should look more into it
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.IAM, create.ErrActionReading, state.ID.String(), state.AssumeRolePolicy.String(), err),
			err.Error(),
		)
		return
	}

	policyToSet, err := verify.PolicyToSet(state.AssumeRolePolicy.ValueString(), assumeRolePolicy)
	if err != nil {
		// TODO: I don't this this is right error, should look more into it
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.IAM, create.ErrActionReading, state.ID.String(), state.AssumeRolePolicy.String(), err),
			err.Error(),
		)
		return
	}
	state.AssumeRolePolicy = fwtypes.IAMPolicyValue(policyToSet)

	// inlinePolicies, err := readRoleInlinePolicies(ctx, aws.StringValue(role.RoleName), meta)
	// if err != nil {
	// // TODO: figure out this error
	// return
	// // return sdkdiag.AppendErrorf(diags, "reading inline policies for IAM role %s, error: %s", d.Id(), err)
	// }

	// var configPoliciesList []*iam.PutRolePolicyInput
	// if v := d.Get("inline_policy").(*schema.Set); v.Len() > 0 {
	// configPoliciesList = expandRoleInlinePolicies(aws.StringValue(role.RoleName), v.List())
	// }

	// if !inlinePoliciesEquivalent(inlinePolicies, configPoliciesList) {
	// if err := d.Set("inline_policy", flattenRoleInlinePolicies(inlinePolicies)); err != nil {
	// return sdkdiag.AppendErrorf(diags, "setting inline_policy: %s", err)
	// }
	// }

	// policyARNs, err := findRoleAttachedPolicies(ctx, conn, d.Id())
	// if err != nil {
	// return sdkdiag.AppendErrorf(diags, "reading IAM Policies attached to Role (%s): %s", d.Id(), err)
	// }
	// d.Set("managed_policy_arns", policyARNs)

	setTagsOut(ctx, role.Tags)
	// state.Tags = flex.FlattenFrameworkStringValueMapLegacy(ctx, KeyValueTags(ctx, role.Tags).Map())
	// data.Tags = flex.FlattenFrameworkStringValueMapLegacy(ctx, tags.Map())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r resourceIamRole) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	fmt.Println("Top of Update")
	conn := r.Meta().IAMConn(ctx)

	var plan, state resourceIamRoleData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.AssumeRolePolicy.Equal(state.AssumeRolePolicy) {
		assumeRolePolicy, err := structure.NormalizeJsonString(plan.AssumeRolePolicy.ValueString())
		if err != nil {
			// TODO: update error here
			// return sdkdiag.AppendErrorf(diags, "assume_role_policy (%s) is invalid JSON: %s", assumeRolePolicy, err)
			return
		}

		input := &iam.UpdateAssumeRolePolicyInput{
			RoleName:       aws.String(state.ID.ValueString()),
			PolicyDocument: aws.String(assumeRolePolicy),
		}

		_, err = tfresource.RetryWhen(ctx, propagationTimeout,
			func() (interface{}, error) {
				return conn.UpdateAssumeRolePolicyWithContext(ctx, input)
			},
			func(err error) (bool, error) {
				if tfawserr.ErrMessageContains(err, iam.ErrCodeMalformedPolicyDocumentException, "Invalid principal in policy") {
					return true, err
				}

				return false, err
			},
		)

		if err != nil {
			// TODO: update error
			// return sdkdiag.AppendErrorf(diags, "updating IAM Role (%s) assume role policy: %s", d.Id(), err)
			return
		}
	}

	if !plan.Description.Equal(state.Description) {
		input := &iam.UpdateRoleDescriptionInput{
			RoleName:    aws.String(state.ID.ValueString()),
			Description: aws.String(plan.Description.ValueString()),
		}

		_, err := conn.UpdateRoleDescriptionWithContext(ctx, input)

		if err != nil {
			// TODO: put something there
			// return sdkdiag.AppendErrorf(diags, "updating IAM Role (%s) description: %s", d.Id(), err)
			fmt.Println("Error updating description")
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.IAM, create.ErrActionReading, state.ID.String(), plan.Description.String(), err),
				err.Error(),
			)
			return
		}

		state.Description = plan.Description
	}

	if !plan.MaxSessionDuration.Equal(state.MaxSessionDuration) {
		input := &iam.UpdateRoleInput{
			RoleName:           aws.String(state.ID.ValueString()),
			MaxSessionDuration: aws.Int64(plan.MaxSessionDuration.ValueInt64()),
		}

		_, err := conn.UpdateRoleWithContext(ctx, input)

		if err != nil {
			// TODO: add error here
			fmt.Println("Hit update max session duration error")
			return
			// return sdkdiag.AppendErrorf(diags, "updating IAM Role (%s) MaxSessionDuration: %s", d.Id(), err)
		}
		state.MaxSessionDuration = plan.MaxSessionDuration
	}

	if !plan.PermissionsBoundary.Equal(state.PermissionsBoundary) {
		if !plan.PermissionsBoundary.IsNull() {
			input := &iam.PutRolePermissionsBoundaryInput{
				PermissionsBoundary: aws.String(plan.PermissionsBoundary.ValueString()),
				RoleName:            aws.String(state.ID.ValueString()),
			}

			_, err := conn.PutRolePermissionsBoundaryWithContext(ctx, input)

			if err != nil {
				// TODO: implement this error
				return
				// return sdkdiag.AppendErrorf(diags, "updating IAM Role (%s) permissions boundary: %s", d.Id(), err)
			}
		} else {
			input := &iam.DeleteRolePermissionsBoundaryInput{
				RoleName: aws.String(state.ID.ValueString()),
			}

			_, err := conn.DeleteRolePermissionsBoundaryWithContext(ctx, input)

			if err != nil {
				// TODO: implement error
				return
				// return sdkdiag.AppendErrorf(diags, "deleting IAM Role (%s) permissions boundary: %s", d.Id(), err)
			}
		}

		state.PermissionsBoundary = plan.PermissionsBoundary
	}

	if !plan.TagsAll.Equal(state.TagsAll) {
		fmt.Println("Tags are not equal!")
		err := roleUpdateTags(ctx, conn, plan.ID.ValueString(), state.TagsAll, plan.TagsAll)

		// Some partitions (e.g. ISO) may not support tagging.
		if errs.IsUnsupportedOperationInPartitionError(conn.PartitionID, err) {
			// TODO: implement error here
			fmt.Println("Hit error parition updating!")
			return
			// return append(diags, resourceRoleRead(ctx, d, meta)...)
		}

		if err != nil {
			fmt.Println("Hit error updating!")
			// TODO: implement error here
			// return sdkdiag.AppendErrorf(diags, "updating tags for IAM Role (%s): %s", d.Id(), err)
			return
		}
	} else {
		fmt.Println("Tags are equal")
	}

	if !plan.TagsAll.Equal(state.TagsAll) {
	}

	// TODO: do I need this? If so huh?
	plan.NamePrefix = flex.StringToFramework(ctx, create.NamePrefixFromName(plan.Name.ValueString()))

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	fmt.Println("Hit bottom of update")
}

func FindRoleByName(ctx context.Context, conn *iam.IAM, name string) (*iam.Role, error) {
	input := &iam.GetRoleInput{
		RoleName: aws.String(name),
	}

	return findRole(ctx, conn, input)
}

func findRole(ctx context.Context, conn *iam.IAM, input *iam.GetRoleInput) (*iam.Role, error) {
	output, err := conn.GetRoleWithContext(ctx, input)

	if tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil || output.Role == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output.Role, nil
}

func retryCreateRole(ctx context.Context, conn *iam.IAM, input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	outputRaw, err := tfresource.RetryWhen(ctx, propagationTimeout,
		func() (interface{}, error) {
			return conn.CreateRoleWithContext(ctx, input)
		},
		func(err error) (bool, error) {
			if tfawserr.ErrMessageContains(err, iam.ErrCodeMalformedPolicyDocumentException, "Invalid principal in policy") {
				return true, err
			}

			return false, err
		},
	)

	if err != nil {
		return nil, err
	}

	output, ok := outputRaw.(*iam.CreateRoleOutput)
	if !ok || output == nil || aws.StringValue(output.Role.RoleName) == "" {
		return nil, fmt.Errorf("create IAM role (%s) returned an empty result", aws.StringValue(input.RoleName))
	}

	return output, err
}

func (r resourceIamRole) addRoleManagedPolicies(ctx context.Context, roleName string, policies []*string) error {
	conn := r.Meta().IAMConn(ctx)
	var errs []error

	for _, arn := range policies {
		if err := attachPolicyToRole(ctx, conn, roleName, aws.StringValue(arn)); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func DeleteRole(ctx context.Context, conn *iam.IAM, roleName string, forceDetach, hasInline, hasManaged bool) error {
	if err := deleteRoleInstanceProfiles(ctx, conn, roleName); err != nil {
		return err
	}

	if forceDetach || hasManaged {
		policyARNs, err := findRoleAttachedPolicies(ctx, conn, roleName)

		if err != nil {
			return fmt.Errorf("reading IAM Policies attached to Role (%s): %w", roleName, err)
		}

		if err := deleteRolePolicyAttachments(ctx, conn, roleName, policyARNs); err != nil {
			return err
		}
	}

	if forceDetach || hasInline {
		inlinePolicies, err := findRolePolicyNames(ctx, conn, roleName)

		if err != nil {
			return fmt.Errorf("reading IAM Role (%s) inline policies: %w", roleName, err)
		}

		if err := deleteRoleInlinePolicies(ctx, conn, roleName, inlinePolicies); err != nil {
			return err
		}
	}

	input := &iam.DeleteRoleInput{
		RoleName: aws.String(roleName),
	}
	_, err := tfresource.RetryWhenAWSErrCodeEquals(ctx, propagationTimeout, func() (interface{}, error) {
		return conn.DeleteRoleWithContext(ctx, input)
	}, iam.ErrCodeDeleteConflictException)

	if tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
		return nil
	}

	return err
}

func deleteRoleInstanceProfiles(ctx context.Context, conn *iam.IAM, roleName string) error {
	instanceProfiles, err := findInstanceProfilesForRole(ctx, conn, roleName)

	if tfresource.NotFound(err) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("reading IAM Instance Profiles for Role (%s): %w", roleName, err)
	}

	var errs []error

	for _, instanceProfile := range instanceProfiles {
		instanceProfileName := aws.StringValue(instanceProfile.InstanceProfileName)
		input := &iam.RemoveRoleFromInstanceProfileInput{
			InstanceProfileName: aws.String(instanceProfileName),
			RoleName:            aws.String(roleName),
		}

		_, err := conn.RemoveRoleFromInstanceProfileWithContext(ctx, input)

		if tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
			continue
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("removing IAM Role (%s) from Instance Profile (%s): %w", roleName, instanceProfileName, err))
		}
	}

	return errors.Join(errs...)
}

func findRoleAttachedPolicies(ctx context.Context, conn *iam.IAM, roleName string) ([]string, error) {
	input := &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	}
	var output []string

	err := conn.ListAttachedRolePoliciesPagesWithContext(ctx, input, func(page *iam.ListAttachedRolePoliciesOutput, lastPage bool) bool {
		if page == nil {
			return !lastPage
		}

		for _, v := range page.AttachedPolicies {
			if v != nil {
				output = append(output, aws.StringValue(v.PolicyArn))
			}
		}

		return !lastPage
	})

	if tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	return output, nil
}

func deleteRolePolicyAttachments(ctx context.Context, conn *iam.IAM, roleName string, policyARNs []string) error {
	var errs []error

	for _, policyARN := range policyARNs {
		input := &iam.DetachRolePolicyInput{
			PolicyArn: aws.String(policyARN),
			RoleName:  aws.String(roleName),
		}

		_, err := conn.DetachRolePolicyWithContext(ctx, input)

		if tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
			continue
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("detaching IAM Policy (%s) from Role (%s): %w", policyARN, roleName, err))
		}
	}

	return errors.Join(errs...)
}

func findRolePolicyNames(ctx context.Context, conn *iam.IAM, roleName string) ([]string, error) {
	input := &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	}
	var output []string

	err := conn.ListRolePoliciesPagesWithContext(ctx, input, func(page *iam.ListRolePoliciesOutput, lastPage bool) bool {
		if page == nil {
			return !lastPage
		}

		for _, v := range page.PolicyNames {
			if v != nil {
				output = append(output, aws.StringValue(v))
			}
		}

		return !lastPage
	})

	if tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	return output, nil
}

func deleteRoleInlinePolicies(ctx context.Context, conn *iam.IAM, roleName string, policyNames []string) error {
	var errs []error

	for _, policyName := range policyNames {
		if len(policyName) == 0 {
			continue
		}

		input := &iam.DeleteRolePolicyInput{
			PolicyName: aws.String(policyName),
			RoleName:   aws.String(roleName),
		}

		_, err := conn.DeleteRolePolicyWithContext(ctx, input)

		if tfawserr.ErrCodeEquals(err, iam.ErrCodeNoSuchEntityException) {
			continue
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("deleting IAM Role (%s) policy (%s): %w", roleName, policyName, err))
		}
	}

	return errors.Join(errs...)
}

func expandRoleInlinePolicies(roleName string, tfPoliciesMap map[string]string) []*iam.PutRolePolicyInput {
	if len(tfPoliciesMap) == 0 {
		return nil
	}

	var apiObjects []*iam.PutRolePolicyInput

	for policyName, policyDocument := range tfPoliciesMap {
		fmt.Println(fmt.Sprintf("policyName: %s", policyName))
		fmt.Println(fmt.Sprintf("policyDocument: %s", policyDocument))
		apiObject := expandRoleInlinePolicy(roleName, policyName, policyDocument)

		if apiObject == nil {
			continue
		}

		apiObjects = append(apiObjects, apiObject)
	}

	return apiObjects
}

func expandRoleInlinePolicy(roleName string, policyName string, policyDocument string) *iam.PutRolePolicyInput {
	apiObject := &iam.PutRolePolicyInput{}

	apiObject.PolicyName = aws.String(policyName)
	apiObject.PolicyDocument = aws.String(policyDocument)
	apiObject.RoleName = aws.String(roleName)

	return apiObject
}

func (r resourceIamRole) addRoleInlinePolicies(ctx context.Context, policies []*iam.PutRolePolicyInput) error {
	conn := r.Meta().IAMConn(ctx)

	var errs *multierror.Error
	for _, policy := range policies {
		if len(aws.StringValue(policy.PolicyName)) == 0 || len(aws.StringValue(policy.PolicyDocument)) == 0 {
			continue
		}

		if _, err := conn.PutRolePolicyWithContext(ctx, policy); err != nil {
			newErr := fmt.Errorf("adding inline policy (%s): %w", aws.StringValue(policy.PolicyName), err)
			errs = multierror.Append(errs, newErr)
		}
	}

	return errs.ErrorOrNil()
}

// func (r resourceIamRole) readRoleInlinePolicies(ctx context.Context, roleName string) ([]*iam.PutRolePolicyInput, error) {
// conn := r.Meta().IAMConn(ctx)

// policyNames, err := findRolePolicyNames(ctx, conn, roleName)

// if err != nil {
// return nil, err
// }

// var apiObjects []*iam.PutRolePolicyInput
// for _, policyName := range policyNames {
// output, err := conn.GetRolePolicyWithContext(ctx, &iam.GetRolePolicyInput{
// RoleName:   aws.String(roleName),
// PolicyName: aws.String(policyName),
// })

// if err != nil {
// return nil, err
// }

// policy, err := url.QueryUnescape(aws.StringValue(output.PolicyDocument))
// if err != nil {
// return nil, err
// }

// p, err := verify.LegacyPolicyNormalize(policy)
// if err != nil {
// return nil, fmt.Errorf("policy (%s) is invalid JSON: %w", p, err)
// }

// apiObject := &iam.PutRolePolicyInput{
// RoleName:       aws.String(roleName),
// PolicyDocument: aws.String(p),
// PolicyName:     aws.String(policyName),
// }

// apiObjects = append(apiObjects, apiObject)
// }

// return apiObjects, nil
// }
