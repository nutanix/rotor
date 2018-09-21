/*
Copyright 2018 Turbine Labs, Inc.

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

package v2

import (
	"errors"
	"fmt"
	"github.com/turbinelabs/codec"
	"github.com/turbinelabs/nonstdlib/flag/usage"
	"github.com/turbinelabs/rotor/xds/collector"
	"log"
	"os"
	"strings"

	"github.com/turbinelabs/api"
	"github.com/turbinelabs/cli/command"
	tbnflag "github.com/turbinelabs/nonstdlib/flag"
	"github.com/turbinelabs/rotor"
	"github.com/turbinelabs/rotor/updater"
	"github.com/turbinelabs/rotor/xds/adapter"
)

const envoyV2Description = `{{ul "EXPERIMENTAL"}} Connects to a running Envoy
CDS server and updates clusters stored in the Turbine Labs API at startup
and periodically thereafter.

Depending on parameters, uses JSON or GRPC to load clusters and will use
results to resolve corresponding instances statically or via configured v2 EDS or
 v1 SDS servers that are provided in CDS results.
`

type Bin struct {
	BinId string	`json:"binid"`
	Host string		`json:"host"`
	Port int		`json:"port"`
}

func (b *Bin) Addr() string {
	return fmt.Sprintf("%s:%d", b.Host, b.Port)
}

type Bins []Bin

func readConfig(filePath string) Bins {
	codec := codec.NewYaml()

	var bins Bins

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	if err := codec.Decode(file, &bins); err != nil {
		log.Fatalf("Failed to load bins from config file: %v", err)
	}
	return bins
}

// Cmd configures the parameters needed for running rotor against a V2
// envoy CDS server, over JSON or GRPC.
func Cmd(updaterFlags rotor.UpdaterFromFlags) *command.Cmd {
	cmd := &command.Cmd{
		Name:        "exp-envoy-cds-v2",
		Summary:     "envoy CDS v2 collector [EXPERIMENTAL]",
		Usage:       "[OPTIONS]",
		Description: envoyV2Description,
	}

	flags := tbnflag.Wrap(&cmd.Flags)

	r := &runner{
		updaterFlags: updaterFlags,
		format:       tbnflag.NewChoice("grpc", "json").WithDefault("grpc"),
	}

	flags.StringVar(
		&r.configFile,
		"config",
		"gds_config.yaml",
		usage.Required("Global Discovery Service config file name."),
	)

	flags.Var(&r.format, "format", "Format of CDS being called.")

	cmd.Runner = r

	return cmd
}

type runner struct {
	updaterFlags rotor.UpdaterFromFlags
	configFile   string
	format       tbnflag.Choice
}

func mergeClusters(accumulator, newData []api.Cluster)  []api.Cluster {
	duplicate := make([]bool, len(newData))
	for i, baseItem := range accumulator {
		for j, newItem := range newData {
			if baseItem.Name == newItem.Name {
				accumulator[i].Instances = append(baseItem.Instances, newItem.Instances...)
				duplicate[j] = true
				break
			}
		}
	}

	for i := range duplicate {
		if !duplicate[i] {
			accumulator = append(accumulator, newData[i])
		}
	}

	return accumulator
}

func (r *runner) Run(cmd *command.Cmd, args []string) command.CmdErr {
	bins := readConfig(r.configFile)

	if err := r.updaterFlags.Validate(); err != nil {
		return cmd.BadInput(err)
	}

	u, err := r.updaterFlags.Make()
	if err != nil {
		return cmd.Error(err)
	}

	isJSON := r.format.String() == "json"

	collectors := make([]collector.ClusterCollector, len(bins))
	for i, bin := range bins {
		curCollector, err := adapter.NewClusterCollector(tbnflag.NewHostPort(bin.Addr()), u.ZoneName(), isJSON, bin.BinId)
		if err != nil {
			return cmd.Error(err)
		}
		collectors[i] = curCollector
		defer collectors[i].Close()
	}

	updater.Loop(
		u,
		func() ([]api.Cluster, error) {
			tbnClusters := make([]api.Cluster, 0)
			for _, curCollector := range collectors {
				tmpClusters, errMap := curCollector.Collect()
				if len(errMap) > 0 {
					return nil, mkError(errMap)
				}
				tbnClusters = mergeClusters(tbnClusters, tmpClusters)
			}

			if len(tbnClusters) == 0 {
				return nil, errors.New("no clusters found, skipping update")
			}

			return tbnClusters, nil
		},
	)

	return command.NoError()
}

func mkError(errMap map[string][]error) error {
	b := &strings.Builder{}
	for c, errs := range errMap {
		for _, e := range errs {
			if b.Len() > 0 {
				b.WriteRune('\n')
			}
			b.WriteString("Error handling CDS update for cluster ")
			b.WriteString(c)
			b.WriteRune(' ')
			b.WriteString(e.Error())
		}
	}
	return errors.New(b.String())
}
