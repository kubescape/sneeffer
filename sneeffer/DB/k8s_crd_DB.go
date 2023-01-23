package DB

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/kubescape/sneeffer/internal/config"
	"github.com/kubescape/sneeffer/internal/logger"
	"github.com/kubescape/sneeffer/sneeffer/container_profiling"
	global_data "github.com/kubescape/sneeffer/sneeffer/global_data/k8s"
	"github.com/kubescape/sneeffer/sneeffer/network_policy"
	"github.com/kubescape/sneeffer/sneeffer/utils"
	"github.com/kubescape/sneeffer/sneeffer/vuln"

	"gopkg.in/yaml.v2"
	k8snetworkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextension "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	k8sapierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	summaryType                    = "summary"
	fullDetailedType               = "fullDetailed"
	containerProfilingType         = "containerProfiling"
	networkPolicyType              = "networkPolicy"
	allowedCharsForK8sResourceName = "abcdefghijklmnopqrstuvwxyz0123456789-."
)

type DBClient struct {
	k8sClient *apiextension.Clientset
}

type CRClient struct {
	restClient rest.Interface
}

type RuntimeVulnDetailed struct {
	v1.TypeMeta   `json:",inline"`
	v1.ObjectMeta `json:"metadata,omitempty"`
	Spec          vuln.VulnDetailed `json:"spec"`
}

type RuntimeVulnSummary struct {
	v1.TypeMeta   `json:",inline"`
	v1.ObjectMeta `json:"metadata,omitempty"`
	Spec          vuln.VulnSummary `json:"spec"`
}

type ContainerProfiling struct {
	v1.TypeMeta   `json:",inline"`
	v1.ObjectMeta `json:"metadata,omitempty"`
	Spec          container_profiling.SeccompData `json:"spec"`
}

type NetworkPolicy struct {
	v1.TypeMeta   `json:",inline"`
	v1.ObjectMeta `json:"metadata,omitempty"`
	Spec          network_policy.NetworkPolicyGen `json:"spec"`
}

var client *DBClient
var restConfig *rest.Config

var groupNameFullCRDetailes string
var pluralNameFullCRDetailes string
var groupVersionFullCRDetailes string
var kindFullCRDetailes string

var groupNameSummaryCR string
var pluralNameSummaryCR string
var groupVersionSummaryCR string
var kindSummaryCR string

var groupNameContainerProfilingCR string
var groupVersionContainerProfilingCR string
var kindContainerProfilingCR string
var pluralNameContainerProfilingCR string

var groupNameNetworkPolicyCR string
var groupVersionNetworkPolicyCR string
var kindNetworkPolicyCR string
var pluralNameNetworkPolicyCR string

func (in *RuntimeVulnSummary) DeepCopyInto(out *RuntimeVulnSummary) {
	out.TypeMeta = in.TypeMeta
	out.ObjectMeta = in.ObjectMeta
	out.Spec = in.Spec
}

func (in *RuntimeVulnSummary) DeepCopyObject() runtime.Object {
	out := RuntimeVulnSummary{}
	in.DeepCopyInto(&out)

	return &out
}

func (in *RuntimeVulnDetailed) DeepCopyInto(out *RuntimeVulnDetailed) {
	out.TypeMeta = in.TypeMeta
	out.ObjectMeta = in.ObjectMeta
	out.Spec = in.Spec
}

func (in *RuntimeVulnDetailed) DeepCopyObject() runtime.Object {
	out := RuntimeVulnDetailed{}
	in.DeepCopyInto(&out)

	return &out
}

func (in *ContainerProfiling) DeepCopyInto(out *ContainerProfiling) {
	out.TypeMeta = in.TypeMeta
	out.ObjectMeta = in.ObjectMeta
	out.Spec = in.Spec
}

func (in *ContainerProfiling) DeepCopyObject() runtime.Object {
	out := ContainerProfiling{}
	in.DeepCopyInto(&out)

	return &out
}

func (in *NetworkPolicy) DeepCopyInto(out *NetworkPolicy) {
	out.TypeMeta = in.TypeMeta
	out.ObjectMeta = in.ObjectMeta
	out.Spec = in.Spec
}

func (in *NetworkPolicy) DeepCopyObject() runtime.Object {
	out := NetworkPolicy{}
	in.DeepCopyInto(&out)

	return &out
}

func parseCRD(CRDPath string) (*apiextensionsv1.CustomResourceDefinition, error) {
	crd := &apiextensionsv1.CustomResourceDefinition{}
	CRDbytes, err := utils.FileBytes(CRDPath)
	if err != nil {
		return nil, err
	}
	err = k8syaml.Unmarshal(CRDbytes, crd)
	if err != nil {
		return nil, err
	}

	return crd, nil
}

func CreateCRDs() error {
	err := connectToDB()
	if err != nil {
		return err
	}

	if config.IsRelaventCVEServiceEnabled() {
		CRDFullDetailedPath, _ := os.LookupEnv("crdFullDetailedPath")
		CRDFullDetailed, err := parseCRD(CRDFullDetailedPath)
		if err != nil {
			logger.Print(logger.ERROR, false, "CreateCRDs: fail on parse CRD of crdFullDetailedPath\n")
			return err
		}
		groupNameFullCRDetailes = CRDFullDetailed.Spec.Group
		groupVersionFullCRDetailes = CRDFullDetailed.Spec.Versions[0].Name
		kindFullCRDetailes = CRDFullDetailed.Spec.Names.Kind
		pluralNameFullCRDetailes = CRDFullDetailed.Spec.Names.Plural
		logger.Print(logger.DEBUG, false, "kindFullCRDetailes %s\n", kindFullCRDetailes)
		_, err = client.k8sClient.ApiextensionsV1().CustomResourceDefinitions().Create(global_data.GlobalHTTPContext, CRDFullDetailed, v1.CreateOptions{})
		if err != nil && !k8sapierrors.IsAlreadyExists(err) {
			logger.Print(logger.ERROR, false, "CreateCRDs: fail create CRD of crdFullDetailedPath\n")
			return err
		}

		CRDVulnSummaryPath, _ := os.LookupEnv("crdVulnSummaryPath")
		CRDVulnSummary, err := parseCRD(CRDVulnSummaryPath)
		if err != nil {
			logger.Print(logger.ERROR, false, "CreateCRDs: fail on parse CRD of crdVulnSummaryPath\n")
			return err
		}
		groupNameSummaryCR = CRDVulnSummary.Spec.Group
		groupVersionSummaryCR = CRDVulnSummary.Spec.Versions[0].Name
		kindSummaryCR = CRDVulnSummary.Spec.Names.Kind
		pluralNameSummaryCR = CRDVulnSummary.Spec.Names.Plural
		logger.Print(logger.DEBUG, false, "kindSummaryCR %s\n", kindSummaryCR)
		_, err = client.k8sClient.ApiextensionsV1().CustomResourceDefinitions().Create(global_data.GlobalHTTPContext, CRDVulnSummary, v1.CreateOptions{})
		if err != nil && !k8sapierrors.IsAlreadyExists(err) {
			logger.Print(logger.ERROR, false, "CreateCRDs: fail create CRD of crdVulnSummaryPath\n")
			return err
		}
	}

	if config.IsContainerProfilingServiceEnabled() {
		groupNameContainerProfilingCR = "security-profiles-operator.x-k8s.io"
		groupVersionContainerProfilingCR = "v1beta1"
		kindContainerProfilingCR = "SeccompProfile"
		pluralNameContainerProfilingCR = "seccompprofiles"
	}

	if config.IsMonitorNetworkingServiceEnabled() {
		CRDNetworkPolicyPath, _ := os.LookupEnv("crdNetworkPolicyPath")
		CRDNetworkPolicy, err := parseCRD(CRDNetworkPolicyPath)
		if err != nil {
			logger.Print(logger.ERROR, false, "CreateCRDs: fail on parse CRD of CRDNetworkPolicyPath\n")
			return err
		}
		groupNameNetworkPolicyCR = CRDNetworkPolicy.Spec.Group
		groupVersionNetworkPolicyCR = CRDNetworkPolicy.Spec.Versions[0].Name
		kindNetworkPolicyCR = CRDNetworkPolicy.Spec.Names.Kind
		pluralNameNetworkPolicyCR = CRDNetworkPolicy.Spec.Names.Plural
		logger.Print(logger.DEBUG, false, "kindNetworkPolicyCR %s\n", kindNetworkPolicyCR)
		_, err = client.k8sClient.ApiextensionsV1().CustomResourceDefinitions().Create(global_data.GlobalHTTPContext, CRDNetworkPolicy, v1.CreateOptions{})
		if err != nil && !k8sapierrors.IsAlreadyExists(err) {
			logger.Print(logger.ERROR, false, "CreateCRDs: fail create CRD of CRDNetworkPolicyPath\n")
			return err
		}
	}
	return nil
}

func connectToDB() error {
	var err error
	var home string
	var exist bool
	var configPath string
	if client != nil {
		return nil
	}

	restConfig, err = rest.InClusterConfig()
	if err != nil {
		logger.Print(logger.DEBUG, false, "InClusterConfig err %v\n", err)
		home, exist = os.LookupEnv("HOME")
		if !exist {
			home = "/root"
		}
		configPath = filepath.Join(home, ".kube", "config")
		restConfig, err = clientcmd.BuildConfigFromFlags("", configPath)
		if err != nil {
			return err
		}
	}

	clientset, err := apiextension.NewForConfig(restConfig)
	if err != nil {
		return err
	}

	client = &DBClient{
		k8sClient: clientset,
	}

	return nil
}

func getGroupName(CRType string) string {
	if CRType == summaryType {
		return groupNameSummaryCR
	} else if CRType == fullDetailedType {
		return groupNameFullCRDetailes
	} else if CRType == networkPolicyType {
		return groupNameNetworkPolicyCR
	}
	return groupNameContainerProfilingCR
}

func getGroupVersion(CRType string) string {
	if CRType == summaryType {
		return groupVersionSummaryCR
	} else if CRType == fullDetailedType {
		return groupVersionFullCRDetailes
	} else if CRType == networkPolicyType {
		return groupVersionNetworkPolicyCR
	}
	return groupVersionContainerProfilingCR
}

func getGroupKind(CRType string) string {
	if CRType == summaryType {
		return kindSummaryCR
	} else if CRType == fullDetailedType {
		return kindFullCRDetailes
	} else if CRType == networkPolicyType {
		return kindNetworkPolicyCR
	}
	return kindContainerProfilingCR
}

func getPluralName(CRType string) string {
	if CRType == summaryType {
		return pluralNameSummaryCR
	} else if CRType == fullDetailedType {
		return pluralNameFullCRDetailes
	} else if CRType == networkPolicyType {
		return pluralNameNetworkPolicyCR
	}
	return pluralNameContainerProfilingCR
}

func newCRClient(CRType string) (*CRClient, error) {
	config := *restConfig
	config.ContentConfig.GroupVersion = &schema.GroupVersion{Group: getGroupName(CRType), Version: getGroupVersion(CRType)}
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}

	return &CRClient{restClient: client}, nil
}

func SetDataInDB(vulnData *vuln.ProccesedVulnData, containerProfilingData *container_profiling.SeccompData, np *k8snetworkingv1.NetworkPolicy, resourceName, service string) error {
	err := connectToDB()
	if err != nil {
		return err
	}

	resourceName = strings.ReplaceAll(resourceName, ":", ".tag-")
	resourceName = utils.ReplaceChars(resourceName, allowedCharsForK8sResourceName, "-")

	if config.IsRelaventCVEServiceEnabled() && service == config.RELAVENT_CVES_SERVICE {
		CRSummaryClient, err := newCRClient(summaryType)
		if err != nil {
			return err
		}

		vulnSummaryResult := RuntimeVulnSummary{}
		vulnSummary := &RuntimeVulnSummary{
			TypeMeta: v1.TypeMeta{
				APIVersion: getGroupName(summaryType) + "/" + getGroupVersion(summaryType),
				Kind:       getGroupKind(summaryType),
			},
			ObjectMeta: v1.ObjectMeta{
				Name: resourceName,
			},
			Spec: vuln.VulnSummary{
				ImageName:       vulnData.DataSummary.ImageName,
				K8sAncestorName: vulnData.DataSummary.K8sAncestorName,
				VulnSummaryData: vuln.VulnSummaryData{
					ImageCVEsNumber:   vulnData.DataSummary.VulnSummaryData.ImageCVEsNumber,
					RuntimeCVEsNumber: vulnData.DataSummary.VulnSummaryData.RuntimeCVEsNumber,
					Description:       vulnData.DataSummary.VulnSummaryData.Description,
				},
			},
		}

		err = CRSummaryClient.restClient.Post().Resource(getPluralName(summaryType)).Body(vulnSummary).Do(global_data.GlobalHTTPContext).Into(&vulnSummaryResult)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				logger.Print(logger.INFO, false, "%s already exists, check if need to update vulns\n", resourceName)
				err = CRSummaryClient.restClient.Get().Resource(getPluralName(summaryType)).Name(resourceName).Do(global_data.GlobalHTTPContext).Into(&vulnSummaryResult)
				if err != nil {
					logger.Print(logger.WARNING, false, "fail to get resource %s for check if update needed with err %v\n", resourceName, err)
				} else {
					if equal := reflect.DeepEqual(vulnSummaryResult.Spec, vulnSummary.Spec); !equal {
						logger.Print(logger.INFO, false, "the vuln data of resource %s has changed, updating\n", resourceName)
						vulnSummary.ObjectMeta.ResourceVersion = vulnSummaryResult.GetObjectMeta().GetResourceVersion()
						err = CRSummaryClient.restClient.Put().Resource(getPluralName(summaryType)).Name(vulnSummary.GetName()).Body(vulnSummary).Do(global_data.GlobalHTTPContext).Into(&vulnSummaryResult)
						if err != nil {
							logger.Print(logger.ERROR, false, "fail to update resource %s with err %v\n", resourceName, err)
						}
					} else {
						logger.Print(logger.INFO, false, "the vuln data of resource %s not changed, no update is needed\n", resourceName)
					}
				}
			} else {
				return err
			}
		}
		logger.Print(logger.INFO, false, "please run the following command to see the result summary: kubectl get %s.%s %s -o yaml\n", getPluralName(summaryType), getGroupName(summaryType), resourceName)

		CRFullDetailedClient, err := newCRClient(fullDetailedType)
		if err != nil {
			return err
		}

		vulnFullDetailedResult := RuntimeVulnDetailed{}
		vulnFullDetailed := &RuntimeVulnDetailed{
			TypeMeta: v1.TypeMeta{
				APIVersion: getGroupName(fullDetailedType) + "/" + getGroupVersion(fullDetailedType),
				Kind:       getGroupKind(fullDetailedType),
			},
			ObjectMeta: v1.ObjectMeta{
				Name: resourceName,
			},
			Spec: vulnData.DataDetailed,
		}

		err = CRFullDetailedClient.restClient.Post().Resource(getPluralName(fullDetailedType)).Body(vulnFullDetailed).Do(global_data.GlobalHTTPContext).Into(&vulnFullDetailedResult)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				logger.Print(logger.INFO, false, "%s already exists, check if need to update vulns\n", resourceName)
				err = CRFullDetailedClient.restClient.Get().Resource(getPluralName(fullDetailedType)).Name(resourceName).Do(global_data.GlobalHTTPContext).Into(&vulnFullDetailedResult)
				if err != nil {
					logger.Print(logger.WARNING, false, "fail to get resource %s for check if update needed with err %v\n", resourceName, err)
				} else {
					if equal := reflect.DeepEqual(vulnFullDetailedResult.Spec, vulnFullDetailed.Spec); !equal {
						logger.Print(logger.INFO, false, "the vuln data of resource %s has changed, updating\n", resourceName)
						vulnFullDetailed.ObjectMeta.ResourceVersion = vulnFullDetailedResult.GetObjectMeta().GetResourceVersion()
						err = CRFullDetailedClient.restClient.Put().Resource(getPluralName(fullDetailedType)).Name(vulnFullDetailed.GetName()).Body(vulnFullDetailed).Do(global_data.GlobalHTTPContext).Into(&vulnFullDetailedResult)
						if err != nil {
							logger.Print(logger.ERROR, false, "fail to update resource %s with err %v\n", resourceName, err)
						}
					} else {
						logger.Print(logger.INFO, false, "the vuln data of resource %s not changed, no update is needed\n", resourceName)
					}
				}
			} else {
				return err
			}
		}

		logger.Print(logger.INFO, false, "please run the following command to see the result in full detaileds: kubectl get %s.%s %s -o yaml\n", getPluralName(fullDetailedType), getGroupName(fullDetailedType), resourceName)
	}

	if config.IsContainerProfilingServiceEnabled() && service == config.CONTAINER_PROFILING_SERVICE {
		CRContainerProfiling, err := newCRClient(containerProfilingType)
		if err != nil {
			return err
		}

		containerProfilingResult := ContainerProfiling{}
		containerProfiling := &ContainerProfiling{
			TypeMeta: v1.TypeMeta{
				APIVersion: getGroupName(containerProfilingType) + "/" + getGroupVersion(containerProfilingType),
				Kind:       getGroupKind(containerProfilingType),
			},
			ObjectMeta: v1.ObjectMeta{
				Name: resourceName,
			},
			Spec: *containerProfilingData,
		}

		err = CRContainerProfiling.restClient.Post().Resource(getPluralName(containerProfilingType)).Namespace("security-profiles-operator").Body(containerProfiling).Do(global_data.GlobalHTTPContext).Into(&containerProfilingResult)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				logger.Print(logger.INFO, false, "%s already exists, check if need to update vulns\n", resourceName)
				err = CRContainerProfiling.restClient.Get().Resource(getPluralName(containerProfilingType)).Namespace("security-profiles-operator").Name(resourceName).Do(global_data.GlobalHTTPContext).Into(&containerProfilingResult)
				if err != nil {
					logger.Print(logger.WARNING, false, "fail to get resource %s for check if update needed with err %v\n", resourceName, err)
				} else {
					if equal := reflect.DeepEqual(containerProfilingResult.Spec, containerProfiling.Spec); !equal {
						logger.Print(logger.INFO, false, "the vuln data of resource %s has changed, updating\n", resourceName)
						containerProfiling.ObjectMeta.ResourceVersion = containerProfilingResult.GetObjectMeta().GetResourceVersion()
						err = CRContainerProfiling.restClient.Put().Resource(getPluralName(containerProfilingType)).Namespace("security-profiles-operator").Name(containerProfiling.GetName()).Body(containerProfiling).Do(global_data.GlobalHTTPContext).Into(&containerProfilingResult)
						if err != nil {
							logger.Print(logger.ERROR, false, "fail to update resource %s with err %v\n", resourceName, err)
						}
					} else {
						logger.Print(logger.INFO, false, "the vuln data of resource %s not changed, no update is needed\n", resourceName)
					}
				}
			} else {
				return err
			}
		}
		logger.Print(logger.INFO, false, "please run the following command to see the result in full detaileds: kubectl -n security-profiles-operator get %s.%s %s -o yaml\n", getPluralName(containerProfilingType), getGroupName(containerProfilingType), resourceName)
	}

	if config.IsMonitorNetworkingServiceEnabled() && service == config.MONITOR_NETWORK_SERVICE {
		yamlData, err := yaml.Marshal(*np)
		if err != nil {
			return fmt.Errorf("fail to marshal the yaml of the network policy of k8s resourceName %s with error %s", resourceName, err.Error())
		}

		CRNetworkPolicy, err := newCRClient(networkPolicyType)
		if err != nil {
			return err
		}

		networkPolicyResult := NetworkPolicy{}
		networkPolicy := &NetworkPolicy{
			TypeMeta: v1.TypeMeta{
				APIVersion: getGroupName(networkPolicyType) + "/" + getGroupVersion(networkPolicyType),
				Kind:       getGroupKind(networkPolicyType),
			},
			ObjectMeta: v1.ObjectMeta{
				Name: resourceName,
			},
			Spec: network_policy.NetworkPolicyGen{
				K8sAncestorName: resourceName,
				NetworkPolicy:   string(yamlData),
			},
		}

		err = CRNetworkPolicy.restClient.Post().Resource(getPluralName(networkPolicyType)).Body(networkPolicy).Do(global_data.GlobalHTTPContext).Into(&networkPolicyResult)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				logger.Print(logger.INFO, false, "%s already exists, check if need to update vulns\n", resourceName)
				err = CRNetworkPolicy.restClient.Get().Resource(getPluralName(networkPolicyType)).Name(resourceName).Do(global_data.GlobalHTTPContext).Into(&networkPolicyResult)
				if err != nil {
					logger.Print(logger.WARNING, false, "fail to get resource %s for check if update needed with err %v\n", resourceName, err)
				} else {
					if equal := reflect.DeepEqual(networkPolicyResult.Spec, networkPolicy.Spec); !equal {
						logger.Print(logger.INFO, false, "the vuln data of resource %s has changed, updating\n", resourceName)
						networkPolicy.ObjectMeta.ResourceVersion = networkPolicyResult.GetObjectMeta().GetResourceVersion()
						err = CRNetworkPolicy.restClient.Put().Resource(getPluralName(containerProfilingType)).Namespace("security-profiles-operator").Name(networkPolicy.GetName()).Body(networkPolicy).Do(global_data.GlobalHTTPContext).Into(&networkPolicyResult)
						if err != nil {
							logger.Print(logger.ERROR, false, "fail to update resource %s with err %v\n", resourceName, err)
						}
					} else {
						logger.Print(logger.INFO, false, "the vuln data of resource %s not changed, no update is needed\n", resourceName)
					}
				}
			} else {
				return err
			}
		}
		logger.Print(logger.INFO, false, "please run the following command to see the result in full detaileds: kubectl -n security-profiles-operator get %s.%s %s -o yaml\n", getPluralName(networkPolicyType), getGroupName(networkPolicyType), resourceName)
	}

	return nil
}

func GetDataFromDB(key []byte) []byte {
	return []byte{}
}
