package k8s_watcher

import (
	"armo_sneeffer/internal/logger"
	"armo_sneeffer/sneeffer/DB"
	"armo_sneeffer/sneeffer/aggregator"
	global_data "armo_sneeffer/sneeffer/global_data/k8s"
	"armo_sneeffer/sneeffer/sbom"
	"armo_sneeffer/sneeffer/vuln"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	core "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	STEP_GET_SBOM           = "STEP_GET_SBOM"
	STEP_GET_UNFILTER_VULNS = "STEP_GET_UNFILTER_VULNS"
	STEP_GET_SNIFFER_DATA   = "STEP_GET_SNIFFER_DATA"
)

type k8sTripeletIdentity struct {
	namespace       string
	k8sAncestorType string
	ancestorName    string
}

type watchedContainer struct {
	containerAggregator *aggregator.Aggregator
	sbomObject          *sbom.SbomObject
	vulnObject          *vuln.VulnObject
	imageID             string
	podName             string
	snifferTimer        *time.Timer
	k8sIdentity         k8sTripeletIdentity
	syncChannel         map[string]chan error
}

type ContainerWatcher struct {
	k8sClient         *kubernetes.Clientset
	watchedContainers map[string]*watchedContainer
	nodeName          string
}

var containerWatcher *ContainerWatcher

func getMyNode(clientset *kubernetes.Clientset) (string, error) {
	return "minikube", nil

	namespace, exist := os.LookupEnv("MY_NAMESPACE")
	if !exist {
		return "", fmt.Errorf("getMyNode: MY_NAMESPACE env var not exist")
	}
	name, exist := os.LookupEnv("MY_DAEMONSET_NAME")
	if !exist {
		return "", fmt.Errorf("getMyNode: MY_DAEMONSET_NAME env var not exist")
	}

	_, err := clientset.AppsV1().DaemonSets(namespace).Get(global_data.GlobalHTTPContext, name, v1.GetOptions{})
	if err != nil {
		return "", err
	}

	return "minikube", nil
}

func CreateContainerWatcher() (*ContainerWatcher, error) {
	var err error
	var home string
	var exist bool
	var configPath string

	restConfig, err := rest.InClusterConfig()
	if err != nil {
		home, exist = os.LookupEnv("HOME")
		if !exist {
			home = "/root"
		}
		configPath = filepath.Join(home, ".kube", "config")
		restConfig, err = clientcmd.BuildConfigFromFlags("", configPath)
		if err != nil {
			return nil, err
		}
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	nodeName, err := getMyNode(clientset)
	if err != nil {
		return nil, err
	}

	containerWatcher = &ContainerWatcher{
		k8sClient:         clientset,
		watchedContainers: map[string]*watchedContainer{},
		nodeName:          nodeName,
	}
	return containerWatcher, nil
}

func (containerWatcher *ContainerWatcher) isContainerWatched(containerID string) bool {
	_, exist := containerWatcher.watchedContainers[containerID]
	return exist
}

func getShortContainerID(containerID string) string {
	cont := strings.Split(containerID, "://")
	return cont[1][:12]
}

func getImageID(imageID string) string {
	splitted := strings.Split(imageID, "://")
	return splitted[1]
}

func getK8SResourceName(containerData *watchedContainer) string {
	return "namespace-" + containerData.k8sIdentity.namespace + "." + containerData.k8sIdentity.k8sAncestorType + "-" + containerData.k8sIdentity.ancestorName + ".name-" + containerData.podName
}

func (containerWatcher *ContainerWatcher) afterTimerActions(containerID string, resourceName string) error {
	var err error
	containerData := containerWatcher.watchedContainers[containerID]

	logger.Print(logger.INFO, false, "stop sniffing on containerID %s in k8s resource %s\n", getShortContainerID(containerID), resourceName)
	containerData.containerAggregator.StopAggregate()

	fileList := containerData.containerAggregator.GetContainerRealtimeFileList()
	if err = <-containerData.syncChannel[STEP_GET_SBOM]; err != nil {
		return err
	}
	err = containerData.sbomObject.FilterSbom(fileList)
	if err != nil {
		return err
	}

	if err = <-containerData.syncChannel[STEP_GET_UNFILTER_VULNS]; err != nil {
		return err
	}
	err = containerData.vulnObject.GetFilterVulnerabilities()
	if err != nil {
		return err
	}

	err = DB.SetDataInDB(containerData.vulnObject.GetProcessedData(), resourceName)
	if err != nil {
		return err
	}

	return nil
}

func (containerWatcher *ContainerWatcher) createTimer() *time.Timer {
	snifferTime, exist := os.LookupEnv("snifferTime")
	if !exist {
		logger.Print(logger.WARNING, false, "startTimer: snifferTime env var is no exist\n")
		logger.Print(logger.WARNING, false, "startTimer: sniffing container time will be 5 minutes\n")
		snifferTime = "5"
	}

	sniffTime, err := strconv.Atoi(snifferTime)
	if err != nil {
		logger.Print(logger.ERROR, false, "fail to convert string sniffertimer time to int with err %v\n", err)
		return nil
	}
	timer := time.NewTimer(time.Duration(sniffTime) * time.Minute)
	return timer
}

func (containerWatcher *ContainerWatcher) startTimer(containerID string, resourceName string) {
	container := containerWatcher.watchedContainers[containerID]
	<-container.snifferTimer.C
	err := containerWatcher.afterTimerActions(containerID, resourceName)
	if err != nil {
		logger.Print(logger.ERROR, false, "afterTimerActions: failed with error %v\n", err)
	}
}

func (containerWatcher *ContainerWatcher) StartFindRelaventCVEsInRuntime(containerID string) {
	containerData := containerWatcher.watchedContainers[containerID]
	resourceName := getK8SResourceName(containerData)

	/*phase 1: create sbom to image */
	go containerData.sbomObject.CreateSbomUnfilter(containerData.syncChannel[STEP_GET_SBOM])

	/*phase 2: create sbom to image */
	go containerData.vulnObject.GetImageVulnerabilities(containerData.syncChannel[STEP_GET_UNFILTER_VULNS])

	/*phase 3: create sniffer to image */
	containerData.containerAggregator.StartAggregate(containerData.syncChannel[STEP_GET_SNIFFER_DATA], resourceName, []string{"execve", "execveat", "open", "openat"}, false, false)

	/*phase 4: start timer for sniffing*/
	go containerWatcher.startTimer(containerID, resourceName)
}

func getK8SIdentityTripplet(pod *core.Pod) k8sTripeletIdentity {

	ancestorName := pod.GetName()
	k8sAncestorType := "deployment"
	ancestorSplittedName := strings.Split(pod.GetName(), "-")
	if len(ancestorSplittedName) > 0 {
		ancestorName = ancestorSplittedName[0]
	}

	return k8sTripeletIdentity{
		namespace:       pod.Namespace,
		k8sAncestorType: k8sAncestorType,
		ancestorName:    ancestorName,
	}
}

func (containerWatcher *ContainerWatcher) StartWatchingOnNewContainers() error {
	watcher, err := containerWatcher.k8sClient.CoreV1().Pods("").Watch(global_data.GlobalHTTPContext, v1.ListOptions{FieldSelector: "spec.nodeName=" + containerWatcher.nodeName})
	if err != nil {
		return err
	}

	for {
		event := <-watcher.ResultChan()
		pod, ok := event.Object.(*core.Pod)
		if !ok {
			continue
		}
		switch event.Type {
		case watch.Modified:
			for i := range pod.Status.ContainerStatuses {
				if pod.Status.ContainerStatuses[i].Ready && !containerWatcher.isContainerWatched(pod.Status.ContainerStatuses[i].ContainerID) {
					if strings.Contains(pod.GetName(), "kubescape-sneeffer") {
						continue
					}
					sbomObject := sbom.CreateSbomObject(getImageID(pod.Status.ContainerStatuses[i].ImageID))
					containerWatcher.watchedContainers[pod.Status.ContainerStatuses[i].ContainerID] = &watchedContainer{
						containerAggregator: aggregator.CreateAggregator(getShortContainerID(pod.Status.ContainerStatuses[i].ContainerID), pod.Status.ContainerStatuses[i].State.Running.StartedAt),
						sbomObject:          sbomObject,
						vulnObject:          vuln.CreateVulnObject(getImageID(pod.Status.ContainerStatuses[i].ImageID), sbomObject),
						imageID:             pod.Status.ContainerStatuses[i].ImageID,
						podName:             pod.Name,
						snifferTimer:        containerWatcher.createTimer(),
						k8sIdentity:         getK8SIdentityTripplet(pod),
						syncChannel: map[string]chan error{
							STEP_GET_SBOM:           make(chan error),
							STEP_GET_UNFILTER_VULNS: make(chan error),
							STEP_GET_SNIFFER_DATA:   make(chan error),
						},
					}

					containerWatcher.StartFindRelaventCVEsInRuntime(pod.Status.ContainerStatuses[i].ContainerID)
				}
			}
		case watch.Deleted:
			for i := range pod.Status.ContainerStatuses {
				if pod.Status.ContainerStatuses[i].State.Terminated != nil && containerWatcher.isContainerWatched(pod.Status.ContainerStatuses[i].State.Terminated.ContainerID) {
					//before stop watching create relavent sbom
					if containerWatcher.watchedContainers[pod.Status.ContainerStatuses[i].ContainerID] != nil {
						containerWatcher.watchedContainers[pod.Status.ContainerStatuses[i].ContainerID].snifferTimer.Stop()
						containerWatcher.afterTimerActions(pod.Status.ContainerStatuses[i].ContainerID, getK8SResourceName(containerWatcher.watchedContainers[pod.Status.ContainerStatuses[i].ContainerID]))
					}
				}
			}
		}
	}
}
