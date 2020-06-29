// Copyright 2016-2020 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/googleinterns/sensor-historian/bugreportutils"
	"github.com/googleinterns/sensor-historian/packageutils"
	"github.com/googleinterns/sensor-historian/parseutils"
)

var (
	summaryFormat = flag.String("summary", parseutils.FormatBatteryLevel, "1. batteryLevel 2. totalTime")
	input         = flag.String("input", "", "A bug report or a battery history file generated by `adb shell dumpsys batterystats -c --history-start <start>`")
	csvFile       = flag.String("csv", "", "Output filename to write csv data to.")
	scrubPII      = flag.Bool("scrub", true, "Whether ScrubPII is applied to addresses.")
	multiple      = flag.Bool("multiple", false, "If true, generates the combined results from multiple bugreports. In this case input should be a directory containing bugreports.")
)

func usage() {
	fmt.Println("Incorrect summary argument. Format: --summary=[batteryLevel|totalTime] [--csv=<csv-output-file>]")
	fmt.Println("Single report: --input=<report-file>")
	fmt.Println("Multiple reports: --input=<report-directory> --multiple")
	os.Exit(1)
}

func checkFlags() {
	switch *summaryFormat {
	case parseutils.FormatBatteryLevel:
	case parseutils.FormatTotalTime:
	default:
		usage()
	}

	if *input == "" {
		usage()
	}
}

// processFile processes a single bugreport file, and returns the parsing result as a string.
// Writes csv data to csvWriter if a csv file is specified.
func processFile(filePath string, csvWriter *bufio.Writer, isFirstFile bool) string {
	// Read the whole file
	c, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}
	br, fname, err := bugreportutils.ExtractBugReport(filePath, c)
	if err != nil {
		log.Fatalf("Error getting file contents: %v", err)
	}
	fmt.Printf("Parsing %s\n", fname)

	writer := ioutil.Discard
	if csvWriter != nil && *summaryFormat == parseutils.FormatTotalTime {
		writer = csvWriter
	}

	pkgs, errs := packageutils.ExtractAppsFromBugReport(br)
	if len(errs) > 0 {
		log.Printf("Errors encountered when getting package list: %v\n", errs)
	}
	upm, errs := parseutils.UIDAndPackageNameMapping(br, pkgs)
	if len(errs) > 0 {
		log.Printf("Errors encountered when generating package mapping: %v\n", errs)
	}
	rep := parseutils.AnalyzeHistory(writer, br, *summaryFormat, upm, *scrubPII)

	// Exclude summaries with no change in battery level
	var a []parseutils.ActivitySummary
	for _, s := range rep.Summaries {
		if s.InitialBatteryLevel != s.FinalBatteryLevel {
			a = append(a, s)
		}
	}

	if rep.TimestampsAltered {
		fmt.Println("Some timestamps were changed while processing the log.")
	}
	if len(rep.Errs) > 0 {
		fmt.Println("Errors encountered:")
		for _, err := range rep.Errs {
			fmt.Println(err.Error())
		}
	}
	fmt.Println("\nNumber of summaries ", len(a), "\n")
	for _, s := range a {
		s.Print(&rep.OutputBuffer)
	}

	// Write the battery level summary csv to the csvFile specified
	if csvWriter != nil && *summaryFormat == parseutils.FormatBatteryLevel {
		// The dimension header line is only written if the file is the first one in the directory.
		parseutils.BatteryLevelSummariesToCSV(csvWriter, &a, isFirstFile)
	}

	return rep.OutputBuffer.String()
}

func main() {
	flag.Parse()
	checkFlags()

	var csvWriter *bufio.Writer
	if *csvFile != "" {
		f, err := os.Create(*csvFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		csvWriter = bufio.NewWriter(f)
		defer csvWriter.Flush()

	}
	isFirstFile := true
	if *multiple {
		// Process multiple history files
		filepath.Walk(*input, func(filePath string, f os.FileInfo, err error) error {
			if filePath == *input {
				return nil
			}
			fmt.Println("Processing ", filePath, "...")
			result := processFile(filePath, csvWriter, isFirstFile)
			fmt.Println(result)
			isFirstFile = false
			return nil
		})
	} else {
		result := processFile(*input, csvWriter, isFirstFile)
		fmt.Println(result)
	}
}
