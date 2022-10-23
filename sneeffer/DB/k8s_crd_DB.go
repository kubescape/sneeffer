package DB

import (
	"os"
	"path/filepath"

	"github.com/kubescape/sneeffer/internal/logger"
	global_data "github.com/kubescape/sneeffer/sneeffer/global_data/k8s"
	"github.com/kubescape/sneeffer/sneeffer/utils"
	"github.com/kubescape/sneeffer/sneeffer/vuln"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextension "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	k8sapierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	summaryType      = "summary"
	fullDetailedType = "fullDetailed"
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

func parseCRD(CRDPath string) (*apiextensionsv1.CustomResourceDefinition, error) {
	crd := &apiextensionsv1.CustomResourceDefinition{}
	CRDbytes, err := utils.FileBytes(CRDPath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(CRDbytes, crd)
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
		logger.Print(logger.INFO, false, "InClusterConfig err %v\n", err)
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
	if CRType == "summary" {
		return groupNameSummaryCR
	}
	return groupNameFullCRDetailes
}

func getGroupVersion(CRType string) string {
	if CRType == "summary" {
		return groupVersionSummaryCR
	}
	return groupVersionFullCRDetailes
}

func getGroupKind(CRType string) string {
	if CRType == "summary" {
		return kindSummaryCR
	}
	return kindFullCRDetailes
}

func getPluralName(CRType string) string {
	if CRType == "summary" {
		return pluralNameSummaryCR
	}
	return pluralNameFullCRDetailes
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

func SetDataInDB(vulnData *vuln.ProccesedVulnData, resourceName string) error {
	err := connectToDB()
	if err != nil {
		return err
	}

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
		return err
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
		return err
	}

	logger.Print(logger.INFO, false, "please run the following command to see the result in full detaileds: kubectl get %s.%s %s -o yaml\n", getPluralName(fullDetailedType), getGroupName(fullDetailedType), resourceName)

	return nil
}

func GetDataFromDB(key []byte) []byte {
	return []byte{}
}
