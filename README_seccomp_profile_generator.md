### Seccomp profile generator 

## Goal
    create a seecomp profile for any started container inthe cluster

## Opening
    this feature is still on developing.
    it's behaviour is still not always working as expected.

## Prerequisisties
    in k8s in order to use seccomp profile configured by user, it must be exist on the node of the host of the containers as a file in the following path - /var/lib/kubelet/seccomp.
    the creation of the file in the path above is doing by an operator that need to be install as a prerequisities with the following steps:

    1. kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.10.1/cert-manager.yaml 
    2. kubectl --namespace cert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager
    3. kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/main/deploy/operator.yaml

## feature installation 
    kubectl apply -f https://raw.githubusercontent.com/kubescape/sneeffer/master/kubescape_sneeffer_Daemonset_seccomp_profile_and_relevent_CVEs.yaml

    with the following config map data:

    innerDataDirPath=./data
    kernelObjPath=./resources/ebpf/kernel_obj.o
    snifferEngineLoaderPath=./resources/ebpf/sniffer
    sbomCreatorPath=./resources/sbom/syft
    vulnCreatorPath=./resources/vuln/grype
    snifferTime=1
    loggerVerbose=INFO
    crdFullDetailedPath=./resources/k8s/crd-vuln-full-detailes.yaml
    crdVulnSummaryPath=./resources/k8s/crd-vuln-summary.yaml
    myNode=minikube
    enableContainerProfilingService=true
    enableRelaventCVEsService=false
    
