package main

import (
	"log"
	"os"

	"github.com/kubescape/sneeffer/internal/logger"
	"github.com/kubescape/sneeffer/internal/validator"
	"github.com/kubescape/sneeffer/sneeffer/DB"
	"github.com/kubescape/sneeffer/sneeffer/accumulator"
	"github.com/kubescape/sneeffer/sneeffer/k8s_watcher"

	"github.com/kubescape/sneeffer/internal/config"
)

func waitOnCacheAccumulatorProccessErrorCode(cacheAccumulatorErrorChan chan error) {
	err := <-cacheAccumulatorErrorChan
	if err != nil {
		logger.Print(logger.ERROR, false, "Global Sniffer failed on error %v\n", err)
		os.Exit(1)
	}
}

func main() {
	err := config.ParseConfiguration()
	if err != nil {
		log.Fatalf("error during parsing configuration: %v", err)
	}

	err = validator.CheckPrerequsits()
	if err != nil {
		log.Fatalf("error during check prerequisites: %v", err)
	}

	err = DB.CreateCRDs()
	if err != nil {
		log.Fatalf("error during DB initialization: %v", err)
	}

	cacheAccumulatorErrorChan := make(chan error)
	cachAccumulator := accumulator.CreateCacheAccumulator(10)
	err = cachAccumulator.StartCacheAccumalator(cacheAccumulatorErrorChan, []string{"execve", "execveat", "open", "openat"}, false, false)
	if err != nil {
		log.Fatalf("fail to create cache watcher %v", err)
	}
	go waitOnCacheAccumulatorProccessErrorCode(cacheAccumulatorErrorChan)

	containerWatcher, err := k8s_watcher.CreateContainerWatcher()
	if err != nil {
		log.Fatalf("fail to create container watcher %v", err)
	}
	err = containerWatcher.StartWatchingOnNewContainers()
	if err != nil {
		log.Fatalf("StartWatchingOnNewContainers fail on error %v", err)
	}
}
