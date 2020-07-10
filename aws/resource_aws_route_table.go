package aws

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/terraform-providers/terraform-provider-aws/aws/internal/keyvaluetags"
	tfec2 "github.com/terraform-providers/terraform-provider-aws/aws/internal/service/ec2"
	"github.com/terraform-providers/terraform-provider-aws/aws/internal/service/ec2/finder"
	"github.com/terraform-providers/terraform-provider-aws/aws/internal/service/ec2/waiter"
)

func resourceAwsRouteTable() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsRouteTableCreate,
		Read:   resourceAwsRouteTableRead,
		Update: resourceAwsRouteTableUpdate,
		Delete: resourceAwsRouteTableDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"vpc_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"tags": tagsSchema(),

			"propagating_vgws": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
			},

			"route": routeTableRouteSchema(),

			"owner_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceAwsRouteTableCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	input := &ec2.CreateRouteTableInput{
		VpcId: aws.String(d.Get("vpc_id").(string)),
	}

	log.Printf("[DEBUG] Creating Route Table: %s", input)
	output, err := conn.CreateRouteTable(input)

	if err != nil {
		return fmt.Errorf("error creating Route Table: %s", err)
	}

	d.SetId(aws.StringValue(output.RouteTable.RouteTableId))

	_, err = waiter.RouteTableCreated(conn, d.Id())

	if err != nil {
		return fmt.Errorf("error waiting for Route Table (%s) to become available: %s", d.Id(), err)
	}

	if vgws := d.Get("propagating_vgws").(*schema.Set); vgws.Len() > 0 {
		for _, vgw := range vgws.List() {
			log.Printf("[DEBUG] Enabling Route Table (%s) VGW (%s) route propagation", d.Id(), vgw)
			err = enableVgwRoutePropagation(conn, d.Id(), vgw.(string), 2*time.Minute)

			if err != nil {
				return err
			}
		}
	}

	if routes := d.Get("route").(*schema.Set); routes.Len() > 0 {
		for _, vRoute := range routes.List() {
			err = createRouteTableRoute(conn, d.Id(), vRoute, 5*time.Minute)

			if err != nil {
				return err
			}
		}
	}

	if v := d.Get("tags").(map[string]interface{}); len(v) > 0 {
		if err := keyvaluetags.Ec2CreateTags(conn, d.Id(), v); err != nil {
			return fmt.Errorf("error adding Route Table (%s) tags: %s", d.Id(), err)
		}
	}

	return resourceAwsRouteTableRead(d, meta)
}

func resourceAwsRouteTableRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn
	ignoreTagsConfig := meta.(*AWSClient).IgnoreTagsConfig

	routeTable, err := finder.RouteTableByID(conn, d.Id())

	if isAWSErr(err, tfec2.ErrCodeRouteTableNotFound, "") {
		log.Printf("[WARN] Route Table (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	if err != nil {
		return fmt.Errorf("error reading Route Table (%s): %s", d.Id(), err)
	}

	if routeTable == nil {
		log.Printf("[WARN] Route Table (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	d.Set("owner_id", routeTable.OwnerId)
	d.Set("vpc_id", routeTable.VpcId)

	propagatingVgws := make([]*string, 0, len(routeTable.PropagatingVgws))
	for _, propagatingVgw := range routeTable.PropagatingVgws {
		propagatingVgws = append(propagatingVgws, propagatingVgw.GatewayId)
	}
	if err := d.Set("propagating_vgws", flattenStringSet(propagatingVgws)); err != nil {
		return fmt.Errorf("error setting propagating_vgws: %s", err)
	}

	if err := d.Set("route", schema.NewSet(resourceAwsRouteTableHash, flattenRoutes(routeTable.Routes))); err != nil {
		return fmt.Errorf("error setting route: %s", err)
	}

	// Tags
	if err := d.Set("tags", keyvaluetags.Ec2KeyValueTags(routeTable.Tags).IgnoreAws().IgnoreConfig(ignoreTagsConfig).Map()); err != nil {
		return fmt.Errorf("error setting tags: %s", err)
	}

	return nil
}

func resourceAwsRouteTableUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	if d.HasChange("propagating_vgws") {
		o, n := d.GetChange("propagating_vgws")
		os := o.(*schema.Set)
		ns := n.(*schema.Set)
		remove := os.Difference(ns).List()
		add := ns.Difference(os).List()

		// Now first loop through all the old propagations and disable any obsolete ones
		for _, vgw := range remove {
			id := vgw.(string)

			// Disable the propagation as it no longer exists in the config
			log.Printf(
				"[INFO] Deleting VGW propagation from %s: %s",
				d.Id(), id)
			_, err := conn.DisableVgwRoutePropagation(&ec2.DisableVgwRoutePropagationInput{
				RouteTableId: aws.String(d.Id()),
				GatewayId:    aws.String(id),
			})
			if err != nil {
				return err
			}
		}

		// Make sure we save the state of the currently configured rules
		propagatingVGWs := os.Intersection(ns)
		d.Set("propagating_vgws", propagatingVGWs)

		// Then loop through all the newly configured propagations and enable them
		for _, vgw := range add {
			id := vgw.(string)

			var err error
			for i := 0; i < 5; i++ {
				log.Printf("[INFO] Enabling VGW propagation for %s: %s", d.Id(), id)
				_, err = conn.EnableVgwRoutePropagation(&ec2.EnableVgwRoutePropagationInput{
					RouteTableId: aws.String(d.Id()),
					GatewayId:    aws.String(id),
				})
				if err == nil {
					break
				}

				// If we get a Gateway.NotAttached, it is usually some
				// eventually consistency stuff. So we have to just wait a
				// bit...
				if isAWSErr(err, tfec2.ErrCodeGatewayNotAttached, "") {
					time.Sleep(20 * time.Second)
					continue
				}
			}
			if err != nil {
				return err
			}

			propagatingVGWs.Add(vgw)
			d.Set("propagating_vgws", propagatingVGWs)
		}
	}

	// Check if the route set as a whole has changed
	if d.HasChange("route") {
		o, n := d.GetChange("route")
		ors := o.(*schema.Set).Difference(n.(*schema.Set))
		nrs := n.(*schema.Set).Difference(o.(*schema.Set))

		// Now first loop through all the old routes and delete any obsolete ones
		for _, route := range ors.List() {
			m := route.(map[string]interface{})

			deleteOpts := &ec2.DeleteRouteInput{
				RouteTableId: aws.String(d.Id()),
			}

			if s := m["ipv6_cidr_block"].(string); s != "" {
				deleteOpts.DestinationIpv6CidrBlock = aws.String(s)

				log.Printf(
					"[INFO] Deleting route from %s: %s",
					d.Id(), m["ipv6_cidr_block"].(string))
			}

			if s := m["cidr_block"].(string); s != "" {
				deleteOpts.DestinationCidrBlock = aws.String(s)

				log.Printf(
					"[INFO] Deleting route from %s: %s",
					d.Id(), m["cidr_block"].(string))
			}

			_, err := conn.DeleteRoute(deleteOpts)
			if err != nil {
				return err
			}
		}

		// Make sure we save the state of the currently configured rules
		routes := o.(*schema.Set).Intersection(n.(*schema.Set))
		d.Set("route", routes)

		// Then loop through all the newly configured routes and create them
		for _, route := range nrs.List() {
			m := route.(map[string]interface{})

			opts := ec2.CreateRouteInput{
				RouteTableId: aws.String(d.Id()),
			}

			if s := m["transit_gateway_id"].(string); s != "" {
				opts.TransitGatewayId = aws.String(s)
			}

			if s := m["vpc_peering_connection_id"].(string); s != "" {
				opts.VpcPeeringConnectionId = aws.String(s)
			}

			if s := m["network_interface_id"].(string); s != "" {
				opts.NetworkInterfaceId = aws.String(s)
			}

			if s := m["instance_id"].(string); s != "" {
				opts.InstanceId = aws.String(s)
			}

			if s := m["ipv6_cidr_block"].(string); s != "" {
				opts.DestinationIpv6CidrBlock = aws.String(s)
			}

			if s := m["cidr_block"].(string); s != "" {
				opts.DestinationCidrBlock = aws.String(s)
			}

			if s := m["gateway_id"].(string); s != "" {
				opts.GatewayId = aws.String(s)
			}

			if s := m["egress_only_gateway_id"].(string); s != "" {
				opts.EgressOnlyInternetGatewayId = aws.String(s)
			}

			if s := m["nat_gateway_id"].(string); s != "" {
				opts.NatGatewayId = aws.String(s)
			}

			log.Printf("[INFO] Creating route for %s: %#v", d.Id(), opts)
			err := resource.Retry(5*time.Minute, func() *resource.RetryError {
				_, err := conn.CreateRoute(&opts)

				if isAWSErr(err, "InvalidRouteTableID.NotFound", "") {
					return resource.RetryableError(err)
				}

				if isAWSErr(err, "InvalidTransitGatewayID.NotFound", "") {
					return resource.RetryableError(err)
				}

				if err != nil {
					return resource.NonRetryableError(err)
				}
				return nil
			})
			if isResourceTimeoutError(err) {
				_, err = conn.CreateRoute(&opts)
			}
			if err != nil {
				return fmt.Errorf("Error creating route: %s", err)
			}

			routes.Add(route)
			d.Set("route", routes)
		}
	}

	if d.HasChange("tags") && !d.IsNewResource() {
		o, n := d.GetChange("tags")

		if err := keyvaluetags.Ec2UpdateTags(conn, d.Id(), o, n); err != nil {
			return fmt.Errorf("error updating EC2 Route Table (%s) tags: %s", d.Id(), err)
		}
	}

	return resourceAwsRouteTableRead(d, meta)
}

func resourceAwsRouteTableDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	// First request the routing table since we'll have to disassociate
	// all the subnets first.
	routeTable, err := finder.RouteTableByID(conn, d.Id())

	if isAWSErr(err, tfec2.ErrCodeRouteTableNotFound, "") {
		return nil
	}

	if err != nil {
		return fmt.Errorf("error reading Route Table (%s): %s", d.Id(), err)
	}

	if routeTable == nil {
		return nil
	}

	// Do all the disassociations
	for _, a := range routeTable.Associations {
		log.Printf("[INFO] Disassociating association: %s", *a.RouteTableAssociationId)
		_, err := conn.DisassociateRouteTable(&ec2.DisassociateRouteTableInput{
			AssociationId: a.RouteTableAssociationId,
		})
		if err != nil {
			// First check if the association ID is not found. If this
			// is the case, then it was already disassociated somehow,
			// and that is okay.
			if isAWSErr(err, tfec2.ErrCodeAssociationNotFound, "") {
				err = nil
			}
		}
		if err != nil {
			return err
		}
	}

	log.Printf("[INFO] Deleting Route Table (%s)", d.Id())
	_, err = conn.DeleteRouteTable(&ec2.DeleteRouteTableInput{
		RouteTableId: aws.String(d.Id()),
	})

	if isAWSErr(err, tfec2.ErrCodeRouteTableNotFound, "") {
		return nil
	}

	if err != nil {
		return fmt.Errorf("error deleting Route Table (%s): %s", d.Id(), err)
	}

	_, err = waiter.RouteTableDeleted(conn, d.Id())

	if isAWSErr(err, tfec2.ErrCodeRouteTableNotFound, "") {
		return nil
	}

	if err != nil {
		return fmt.Errorf("error waiting for Route Table (%s) to delete: %s", d.Id(), err)
	}

	return nil
}

func resourceAwsRouteTableHash(v interface{}) int {
	var buf bytes.Buffer
	m, castOk := v.(map[string]interface{})
	if !castOk {
		return 0
	}

	if v, ok := m["ipv6_cidr_block"]; ok {
		buf.WriteString(fmt.Sprintf("%s-", canonicalCidrBlock(v.(string))))
	}

	if v, ok := m["cidr_block"]; ok {
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}

	if v, ok := m["gateway_id"]; ok {
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}

	if v, ok := m["egress_only_gateway_id"]; ok {
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}

	natGatewaySet := false
	if v, ok := m["nat_gateway_id"]; ok {
		natGatewaySet = v.(string) != ""
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}

	instanceSet := false
	if v, ok := m["instance_id"]; ok {
		instanceSet = v.(string) != ""
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}

	if v, ok := m["transit_gateway_id"]; ok {
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}

	if v, ok := m["vpc_peering_connection_id"]; ok {
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}

	if v, ok := m["network_interface_id"]; ok && !(instanceSet || natGatewaySet) {
		buf.WriteString(fmt.Sprintf("%s-", v.(string)))
	}

	return hashcode.String(buf.String())
}

// TODO Tidy up other callers of this - Replace with finder.
// resourceAwsRouteTableStateRefreshFunc returns a resource.StateRefreshFunc that is used to watch
// a RouteTable.
func resourceAwsRouteTableStateRefreshFunc(conn *ec2.EC2, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		resp, err := conn.DescribeRouteTables(&ec2.DescribeRouteTablesInput{
			RouteTableIds: []*string{aws.String(id)},
		})
		if err != nil {
			if isAWSErr(err, "InvalidRouteTableID.NotFound", "") {
				resp = nil
			} else {
				log.Printf("Error on RouteTableStateRefresh: %s", err)
				return nil, "", err
			}
		}

		if resp == nil {
			// Sometimes AWS just has consistency issues and doesn't see
			// our instance yet. Return an empty state.
			return nil, "", nil
		}

		rt := resp.RouteTables[0]
		return rt, "ready", nil
	}
}

// Shared by aws_route_table and aws_default_route_table.
func routeTableRouteSchema() *schema.Schema {
	return &schema.Schema{
		Type:       schema.TypeSet,
		Computed:   true,
		Optional:   true,
		ConfigMode: schema.SchemaConfigModeAttr,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				// Destinations.
				"cidr_block": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.Any(
						validation.StringIsEmpty,
						validateIpv4CIDRNetworkAddress,
					),
				},

				"ipv6_cidr_block": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.Any(
						validation.StringIsEmpty,
						validateIpv6CIDRNetworkAddress,
					),
				},

				// Targets.
				"egress_only_gateway_id": {
					Type:     schema.TypeString,
					Optional: true,
				},

				"gateway_id": {
					Type:     schema.TypeString,
					Optional: true,
				},

				"instance_id": {
					Type:     schema.TypeString,
					Optional: true,
				},

				"nat_gateway_id": {
					Type:     schema.TypeString,
					Optional: true,
				},

				"network_interface_id": {
					Type:     schema.TypeString,
					Optional: true,
				},

				"transit_gateway_id": {
					Type:     schema.TypeString,
					Optional: true,
				},

				"vpc_peering_connection_id": {
					Type:     schema.TypeString,
					Optional: true,
				},
			},
		},
		Set: resourceAwsRouteTableHash,
	}
}

// TODO
// TODO Move these to a per-service internal package and auto-generate where possible.
// TODO

// createRouteTableRoute attempts to create a route in a route table.
// The specified eventual consistency timeout is respected.
// Any error is returned.
func createRouteTableRoute(conn *ec2.EC2, routeTableID string, vRoute interface{}, timeout time.Duration) error {
	mRoute := vRoute.(map[string]interface{})

	input := &ec2.CreateRouteInput{
		RouteTableId: aws.String(routeTableID),
	}

	if vCidrBlock := mRoute["cidr_block"].(string); vCidrBlock != "" {
		input.DestinationCidrBlock = aws.String(vCidrBlock)
	}

	if vIpv6CidrBlock := mRoute["ipv6_cidr_block"].(string); vIpv6CidrBlock != "" {
		input.DestinationIpv6CidrBlock = aws.String(vIpv6CidrBlock)
	}

	if vEgressOnlyGatewayID := mRoute["egress_only_gateway_id"].(string); vEgressOnlyGatewayID != "" {
		input.EgressOnlyInternetGatewayId = aws.String(vEgressOnlyGatewayID)
	}

	if vGatewayID := mRoute["gateway_id"].(string); vGatewayID != "" {
		input.GatewayId = aws.String(vGatewayID)
	}

	if vInstanceID := mRoute["instance_id"].(string); vInstanceID != "" {
		input.InstanceId = aws.String(vInstanceID)
	}

	if vNatGatewayID := mRoute["nat_gateway_id"].(string); vNatGatewayID != "" {
		input.NatGatewayId = aws.String(vNatGatewayID)
	}

	if vNetworkInterfaceID := mRoute["network_interface_id"].(string); vNetworkInterfaceID != "" {
		input.NetworkInterfaceId = aws.String(vNetworkInterfaceID)
	}

	if vTransitGatewayID := mRoute["transit_gateway_id"].(string); vTransitGatewayID != "" {
		input.TransitGatewayId = aws.String(vTransitGatewayID)
	}

	if vVpcPeeringConnectionID := mRoute["vpc_peering_connection_id"].(string); vVpcPeeringConnectionID != "" {
		input.VpcPeeringConnectionId = aws.String(vVpcPeeringConnectionID)
	}

	log.Printf("[DEBUG] Creating Route: %s", input)
	if err := createRoute(conn, input, timeout); err != nil {
		return err
	}

	return nil
}

// enableVgwRoutePropagation attempts to enable VGW route propagation.
// The specified eventual consistency timeout is respected.
// Any error is returned.
func enableVgwRoutePropagation(conn *ec2.EC2, routeTableID, gatewayID string, timeout time.Duration) error {
	input := &ec2.EnableVgwRoutePropagationInput{
		GatewayId:    aws.String(gatewayID),
		RouteTableId: aws.String(routeTableID),
	}

	err := resource.Retry(timeout, func() *resource.RetryError {
		_, err := conn.EnableVgwRoutePropagation(input)

		if isAWSErr(err, tfec2.ErrCodeGatewayNotAttached, "") {
			return resource.RetryableError(err)
		}

		if err != nil {
			return resource.NonRetryableError(err)
		}

		return nil
	})

	if isResourceTimeoutError(err) {
		_, err = conn.EnableVgwRoutePropagation(input)
	}

	if err != nil {
		return fmt.Errorf("error enabling Route Table (%s) VGW (%s) route propagation: %s", routeTableID, gatewayID, err)
	}

	return nil
}

func flattenRoutes(routes []*ec2.Route) []interface{} {
	if routes == nil {
		return []interface{}{}
	}

	vRoutes := []interface{}{}

	for _, route := range routes {
		// Skip routes we didn't create ourselves.
		if aws.StringValue(route.Origin) != ec2.RouteOriginCreateRoute {
			continue
		}

		// Skip VPC Endpoint routes, they are managed via the ModifyVpcEndpoint API.
		if strings.HasPrefix(aws.StringValue(route.DestinationPrefixListId), "vpce-") {
			continue
		}

		mRoute := map[string]interface{}{
			"cidr_block":                aws.StringValue(route.DestinationCidrBlock),
			"ipv6_cidr_block":           aws.StringValue(route.DestinationIpv6CidrBlock),
			"egress_only_gateway_id":    aws.StringValue(route.EgressOnlyInternetGatewayId),
			"gateway_id":                aws.StringValue(route.GatewayId),
			"instance_id":               aws.StringValue(route.InstanceId),
			"nat_gateway_id":            aws.StringValue(route.NatGatewayId),
			"network_interface_id":      aws.StringValue(route.NetworkInterfaceId),
			"transit_gateway_id":        aws.StringValue(route.TransitGatewayId),
			"vpc_peering_connection_id": aws.StringValue(route.VpcPeeringConnectionId),
		}

		vRoutes = append(vRoutes, mRoute)
	}

	return vRoutes
}
