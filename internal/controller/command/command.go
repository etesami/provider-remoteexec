/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package command

import (
	"context"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	commonv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/crossplane/provider-remoteexec/apis/ssh/v1alpha1"
	apisv1alpha1 "github.com/crossplane/provider-remoteexec/apis/v1alpha1"
	sshv1alpha1 "github.com/crossplane/provider-remoteexec/internal/client/ssh"
	"github.com/crossplane/provider-remoteexec/internal/features"
)

const (
	errNotCommand   = "managed resource is not a Command custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

// A NoOpService does nothing.
type NoOpService struct{}

var (
	newNoOpService = func(_ []byte) (interface{}, error) { return &NoOpService{}, nil }
)

// Setup adds a controller that reconciles Command managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.CommandGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}
	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.CommandGroupVersionKind),
		managed.WithExternalConnecter(&connector{
			kube:         mgr.GetClient(),
			usage:        resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			newServiceFn: sshv1alpha1.NewSSHClientwithMap}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...),
		managed.WithManagementPolicies())

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.Command{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube         client.Client
	usage        resource.Tracker
	newServiceFn func(ctx context.Context, creds map[string][]byte) (*ssh.Client, error)
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	logger := log.FromContext(ctx).WithName("[CONNECT]")
	logger.Info("Connecting...")
	cr, ok := mg.(*v1alpha1.Command)
	if !ok {
		return nil, errors.New(errNotCommand)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	cd := pc.Spec.Credentials
	// data, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	data, err := ExtractSecret(ctx, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	svc, err := c.newServiceFn(ctx, data)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{service: svc}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	// A 'client' used to connect to the external resource API. In practice this
	// would be something like an AWS SDK client.
	service interface{}
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	logger := log.FromContext(ctx).WithName("[OBSERVE]")
	cr, ok := mg.(*v1alpha1.Command)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotCommand)
	}

	// anything else than delete, we just update (run the script) again
	msg, err := sshv1alpha1.RunScript(
		ctx, c.service.(*ssh.Client), cr.Spec.ForProvider.Script, cr.Spec.ForProvider.SudoEnabled)

	if err != nil {
		// when there is an error in running script, we just reflect results in status
		// and set conditions accordingly and wait for trigger to be set to true
		// there is nothing for the external resource to be created or updated
		logger.Error(err, "Unable to run the script")
		cr.Status.AtProvider.Output = msg
		cr.Status.AtProvider.StatusCode = err.(*ssh.ExitError).ExitStatus()
		cr.SetConditions(commonv1.Unavailable())
		return managed.ExternalObservation{
			// setting ResourceExists to true, so that create event is not triggered
			// setting ResourceUpToDate to true, so that update event is not triggered
			ResourceExists:   true,
			ResourceUpToDate: true,
		}, nil
	}

	cr.Status.AtProvider.StatusCode = 0
	cr.Status.AtProvider.Output = msg
	cr.SetConditions(commonv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true,
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	logger := log.FromContext(ctx).WithName("[CREATE]")
	logger.Info("Creating...")
	_, ok := mg.(*v1alpha1.Command)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotCommand)
	}

	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	logger := log.FromContext(ctx).WithName("[UPDATE]")
	logger.Info("Updating...")
	_, ok := mg.(*v1alpha1.Command)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotCommand)
	}

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	logger := log.FromContext(ctx).WithName("[DELETE]")
	logger.Info("Deleting...")
	_, ok := mg.(*v1alpha1.Command)
	if !ok {
		return errors.New(errNotCommand)
	}

	return nil
}

// ExtractSecret extracts credentials from a Kubernetes secret with any keys.
func ExtractSecret(ctx context.Context, client client.Client, s xpv1.CommonCredentialSelectors) (map[string][]byte, error) {
	if s.SecretRef == nil {
		return nil, errors.New("cannot extract from secret key when none specified")
	}
	secret := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: s.SecretRef.Namespace, Name: s.SecretRef.Name}, secret); err != nil {
		return nil, errors.Wrap(err, "cannot get credentials secret")
	}
	return secret.Data, nil
}
