// Code generated by internal/generate/servicepackages/main.go; DO NOT EDIT.

package connect

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/names"
)

type servicePackage struct{}

func (p *servicePackage) FrameworkDataSources(ctx context.Context) []func(context.Context) (datasource.DataSourceWithConfigure, error) {
	return []func(context.Context) (datasource.DataSourceWithConfigure, error){}
}

func (p *servicePackage) FrameworkResources(ctx context.Context) []func(context.Context) (resource.ResourceWithConfigure, error) {
	return []func(context.Context) (resource.ResourceWithConfigure, error){}
}

func (p *servicePackage) SDKDataSources(ctx context.Context) map[string]func() *schema.Resource {
	return map[string]func() *schema.Resource{
		"aws_connect_bot_association":             DataSourceBotAssociation,
		"aws_connect_contact_flow":                DataSourceContactFlow,
		"aws_connect_contact_flow_module":         DataSourceContactFlowModule,
		"aws_connect_hours_of_operation":          DataSourceHoursOfOperation,
		"aws_connect_instance":                    DataSourceInstance,
		"aws_connect_instance_storage_config":     DataSourceInstanceStorageConfig,
		"aws_connect_lambda_function_association": DataSourceLambdaFunctionAssociation,
		"aws_connect_prompt":                      DataSourcePrompt,
		"aws_connect_queue":                       DataSourceQueue,
		"aws_connect_quick_connect":               DataSourceQuickConnect,
		"aws_connect_routing_profile":             DataSourceRoutingProfile,
		"aws_connect_security_profile":            DataSourceSecurityProfile,
		"aws_connect_user_hierarchy_group":        DataSourceUserHierarchyGroup,
		"aws_connect_user_hierarchy_structure":    DataSourceUserHierarchyStructure,
	}
}

func (p *servicePackage) SDKResources(ctx context.Context) map[string]func() *schema.Resource {
	return map[string]func() *schema.Resource{
		"aws_connect_bot_association":             ResourceBotAssociation,
		"aws_connect_contact_flow":                ResourceContactFlow,
		"aws_connect_contact_flow_module":         ResourceContactFlowModule,
		"aws_connect_hours_of_operation":          ResourceHoursOfOperation,
		"aws_connect_instance":                    ResourceInstance,
		"aws_connect_instance_storage_config":     ResourceInstanceStorageConfig,
		"aws_connect_lambda_function_association": ResourceLambdaFunctionAssociation,
		"aws_connect_phone_number":                ResourcePhoneNumber,
		"aws_connect_queue":                       ResourceQueue,
		"aws_connect_quick_connect":               ResourceQuickConnect,
		"aws_connect_routing_profile":             ResourceRoutingProfile,
		"aws_connect_security_profile":            ResourceSecurityProfile,
		"aws_connect_user":                        ResourceUser,
		"aws_connect_user_hierarchy_group":        ResourceUserHierarchyGroup,
		"aws_connect_user_hierarchy_structure":    ResourceUserHierarchyStructure,
		"aws_connect_vocabulary":                  ResourceVocabulary,
	}
}

func (p *servicePackage) ServicePackageName() string {
	return names.Connect
}

var ServicePackage = &servicePackage{}
