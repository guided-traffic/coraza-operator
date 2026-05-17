/*
Copyright 2026 Guided Traffic GmbH.

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

// main is the entry point for the Coraza-based reverse-proxy engine binary.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	ctrlzap "sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/guided-traffic/coraza-operator/internal/enginepkg"
)

func main() {
	logger := ctrlzap.New(ctrlzap.UseDevMode(false))

	cfg, err := enginepkg.FromEnv()
	if err != nil {
		logger.Error(err, "invalid configuration")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if runErr := enginepkg.Run(ctx, cfg, logger); runErr != nil {
		logger.Error(runErr, "engine terminated with error")
		fmt.Fprintf(os.Stderr, "engine error: %v\n", runErr)
		os.Exit(1)
	}
}
