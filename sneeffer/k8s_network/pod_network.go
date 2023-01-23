package k8s_network

import (
	"github.com/golang/glog"
	global_data "github.com/kubescape/sneeffer/sneeffer/global_data/k8s"
	core1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

func GetPodsServicesIPs(k8sClient *kubernetes.Clientset, pod *core1.Pod) []string {
	serviceIPs := []string{}
	services := make(map[string]map[string]string)
	podLabels := labels.Set(pod.GetLabels())
	list, err := k8sClient.CoreV1().Services("").List(global_data.GlobalHTTPContext, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	for i := range list.Items {
		if pod.GetNamespace() != list.Items[i].GetNamespace() {
			continue
		}
		services[list.Items[i].GetName()] = make(map[string]string)
		for key := range list.Items[i].Spec.Selector {
			services[list.Items[i].GetName()][key] = list.Items[i].Spec.Selector[key]
		}
	}

	for serviceName := range services {
		for selectorKey := range services[serviceName] {
			labelSelectors, err := labels.Parse(selectorKey + "=" + services[serviceName][selectorKey])
			labelSelectors.Add()
			if err != nil {
				glog.Errorf("failed to parse service labels, service: %s, reason: %s", serviceName, err.Error())
				continue
			}
			if labelSelectors.Matches(podLabels) {
				service, _ := k8sClient.CoreV1().Services(pod.GetNamespace()).Get(global_data.GlobalHTTPContext, serviceName, metav1.GetOptions{})
				serviceIPs = append(serviceIPs, service.Spec.ClusterIPs...)
			}
		}
	}
	return serviceIPs
}
