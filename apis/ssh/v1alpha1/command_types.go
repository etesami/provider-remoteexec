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

package v1alpha1

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// CommandParameters are the configurable fields of a Command.
type CommandParameters struct {
	Command string `json:"command"`
}

// CommandObservation are the observable fields of a Command.
type CommandObservation struct {
	Output     string `json:"output,omitempty"`
	StatusCode string `json:"statusCode,omitempty"`
}

// A CommandSpec defines the desired state of a Command.
type CommandSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       CommandParameters `json:"forProvider"`
}

// A CommandStatus represents the observed state of a Command.
type CommandStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          CommandObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Command is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,remoteexec}
type Command struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CommandSpec   `json:"spec"`
	Status CommandStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CommandList contains a list of Command
type CommandList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Command `json:"items"`
}

// Command type metadata.
var (
	CommandKind             = reflect.TypeOf(Command{}).Name()
	CommandGroupKind        = schema.GroupKind{Group: Group, Kind: CommandKind}.String()
	CommandKindAPIVersion   = CommandKind + "." + SchemeGroupVersion.String()
	CommandGroupVersionKind = SchemeGroupVersion.WithKind(CommandKind)
)

func init() {
	SchemeBuilder.Register(&Command{}, &CommandList{})
}
