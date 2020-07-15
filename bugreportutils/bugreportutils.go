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

// Package bugreportutils is a library of common bugreport parsing functions.
package bugreportutils

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/googleinterns/sensor-historian/historianutils"
	"github.com/googleinterns/sensor-historian/packageutils"
)

const (
	// GPSSensorNumber is the hard-coded sensor number defined in
	// frameworks/base/core/java/android/os/BatteryStats.Sensor
	GPSSensorNumber = -10000

	// TimeLayout is the timestamp layout commonly printed in bug reports.
	TimeLayout = "2006-01-02 15:04:05"
)

var (
	// BugReportSectionRE is a regular expression to match the beginning of a
	// bug report section.
	BugReportSectionRE = regexp.MustCompile(`------\s+(?P<section>.*)\s+-----`)

	// deviceIDRE is a regular expression that matches the "DeviceID" line.
	deviceIDRE = regexp.MustCompile("DeviceID: (?P<deviceID>[0-9]+)")

	// sdkVersionRE is a regular expression that finds sdk version in the
	// System Properties section of a bug report.
	sdkVersionRE = regexp.MustCompile(`\[ro.build.version.sdk\]:` +
		`\s+\[(?P<sdkVersion>\d+)\]`)

	// buildFingerprintRE is a regular expression to match any build
	// fingerprint line in the bugreport.
	buildFingerprintRE = regexp.MustCompile(`Build\s+fingerprint:\s+` +
		`'(?P<build>\S+)'`)

	// modelNameRE is a regular expression that finds the model name line
	// in the System Properties section of a bug report.
	modelNameRE = regexp.MustCompile(`\[ro.product.model\]:\s+` +
		`\[(?P<modelName>.*)\]`)

	// pidRE is a regular expression to match PID to app name and UID.
	pidRE = regexp.MustCompile(`PID #` + `(?P<pid>\d+)` +
		`: ProcessRecord[^:]+:` + `(?P<app>[^/]+)` + `/` + `(?P<uid>.*)` + `}`)

	// sensorLineMMinusRE is a regular expression to match the sensor list line
	// in the sensorservice dump of a bug report from MNC or before.
	sensorLineMMinusRE = regexp.MustCompile(`(?P<sensorName>[^|]+)` + `\|` +
		`(?P<sensorManufacturer>[^|]+)` + `\|` + `(\s*version=` +
		`(?P<versionNumber>\d+)\s*\|)?` + `\s*(?P<sensorTypeString>[^|]+)` +
		`\|` + `\s*(?P<sensorNumber>0x[0-9A-Fa-f]+)\s*` + `\|` + `.*` + `\|` +
		`\s*type=\d+\s*\|` + `\s*(?P<requestMode>[^|]+)` + `\s*\|` +
		`(?P<variableOne>[^|]+)` + `\s*\|` + `(?P<variableTwo>[^|]+)` +
		`\s*\|` + `(?P<batching>[^|]+)` + `\s*\|` + `(?P<wakeUp>[^|]+)`)

	// sensorLine1RE is a regular expression to match the first line of
	// sensor information from the sensor list line in the sensorservice dump
	// in the bugreport starting from NRD42 and onwards.
	sensorLine1RE = regexp.MustCompile(`(?P<sensorNumber>0x?[0-9A-Fa-f]+)` +
		`\)\s*` + `(?P<sensorName>[^|]+)` + `\s*\|` +
		`(?P<sensorManufacturer>[^|]+)` + `\|\s*ver:\s*` +
		`(?P<versionNumber>\d+)` + `\s*\|\s*type:\s*` +
		`(?P<sensorTypeString>[^(]+)` + `\(\d+\)\s*\|` + `\s*perm:\s*` +
		`(?P<sensorPerm>[^|]+)`)

	// sensorLine2RE is a regular expression to match the second line of
	// sensor information from the sensor list line in the sensorservice
	// dump in the bugreport starting from NRD42 and onwards.
	sensorLine2RE = regexp.MustCompile(`\s*(?P<requestMode>[^|]+)` + `\s*\|` +
		`(?P<variableOne>[^|]+)` + `\s*\|` + `(?P<variableTwo>[^|]+)` +
		`\s*\|` + `(?P<batching>[^|]+)` + `\s*\|` + `(?P<wakeUp>[^|]+)`)

	// BatchingDataRE is a regular expression that matches the max and
	// reserved data quantity from the sensor infomration listed in the
	// sensorservice dump of a bug report.
	// e.g FIFO (max,reserved) = (10000, 3000) events
	// BatchingDataRE is used for bugreport starting from NRD42 and onwards.
	BatchingDataRE = regexp.MustCompile(`FIFO\s*\(max,reserved\)\s*=\s*\(` +
		`(?P<maxNum>\d+)` + `,` + `(?P<reservedNum>[^|]+)` + `\) events\s*`)

	// rateRE is a regular expression that matches the minRate/maxRate
	// information listed for each sensor in the sensorservice dump section.
	rateRE = regexp.MustCompile(`=(?P<rateVal>[\-\+]?[0-9]*(\.[0-9]+)+)Hz`)

	// delayRE is a regular expression that matches the maxDelay/minDelay
	// information listed for each sensor in the sensorservice dump section.
	delayRE = regexp.MustCompile(`=(?P<delayVal>[\-\+]?\d+)us`)

	// fifoMaxRE is a regular expression that matches the fifomax information
	// listed for each sensor in the sensorservice dump section,
	// for Android version from MNC or before.
	fifoMaxRE = regexp.MustCompile(`FifoMax=\s*(?P<maxNum>[^|]+)\s*events`)

	// TimeZoneRE is a regular expression to match the timezone string
	// in a bug report.
	TimeZoneRE = regexp.MustCompile(`^\[persist.sys.timezone\]:\s+\[` +
		`(?P<timezone>\S+)\]`)

	// DumpstateRE is a regular expression that matches the time information
	// from the dumpstate line at the start of a bug report.
	DumpstateRE = regexp.MustCompile(`==\sdumpstate:\s` +
		`(?P<timestamp>\d+-\d+-\d+\s\d+:\d+:\d+)`)
)

// Contents returns a map of the contents of each file from the given bytes
// slice, with the key being the file name.
// Supported file formats are text/plain and application/zip.
// For zipped files, each file name will be prepended by the zip file's name.
// An error will be non-nil for processing issues.
func Contents(fname string, b []byte) (map[string][]byte, error) {
	contentType := http.DetectContentType(b)
	switch {
	case strings.Contains(contentType, "text/plain"):
		return map[string][]byte{fname: b}, nil
	case strings.Contains(contentType, "application/zip"):
		return unzipAndExtract(fname, b)
	default:
		return nil, fmt.Errorf("incorrect file format detected: %q",
			contentType)
	}
}

// IsBugReport tries to determine if the given bytes resembles a bug report.
func IsBugReport(b []byte) bool {
	// Check for a few expected lines in all bug reports.
	return DumpstateRE.Match(b) && buildFingerprintRE.Match(b) &&
		BugReportSectionRE.Match(b)
}

// unzipAndExtract unzips the given application/zip format file and returns
// the contents of each file.
// An error will be non-nil for processing issues.
func unzipAndExtract(fname string, b []byte) (map[string][]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("failed to open ZIP file: %v", err)
	}
	files := make(map[string][]byte)
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("error reading from ZIP file: %v", err)
		}
		defer rc.Close()
		var zc bytes.Buffer
		_, err = io.Copy(&zc, rc)
		if err != nil {
			return nil, fmt.Errorf("error copying from ZIP file: %v", err)
		}
		// Don't recursively extract from any sub-ZIP files since we use
		// this to also extract .jar files for Closure.
		files[fname+"~"+f.Name] = zc.Bytes()
	}
	return files, nil
}

// MetaInfo contains metadata about the device being analyzed
type MetaInfo struct {
	DeviceID         string
	SdkVersion       int
	BuildFingerprint string
	ModelName        string
	Sensors          map[int32]SensorInfo
}

// SensorInfo contains basic information about a device's sensor.
type SensorInfo struct {
	Name, Type      string
	Version, Number int32
	// time.Duration in Golang is converted to nanoseconds in JS,
	// so using int64 and naming convention to be clear in$
	TotalTimeMs                int64
	Count                      float32
	RequestMode                string
	MaxDelayInUs, MinDelayInUs int32
	Batch                      bool
	Max, Reserved              int32
	WakeUp                     bool
}

// ParseMetaInfo extracts the device ID, build fingerprint and model name
// from the bug report.
func ParseMetaInfo(input string) (*MetaInfo, error) {
	var deviceID, buildFingerprint, modelName string
	sdkVersion := -1
	for _, line := range strings.Split(input, "\n") {
		if m, result := historianutils.SubexpNames(deviceIDRE, line); m {
			deviceID = result["deviceID"]
		} else if m, result := historianutils.SubexpNames(sdkVersionRE, line); m {
			sdk, err := strconv.Atoi(result["sdkVersion"])
			if err != nil {
				return nil, err
			}
			sdkVersion = sdk
		} else if m, result := historianutils.SubexpNames(buildFingerprintRE, line); m && buildFingerprint == "" {
			// Only the first instance of this line in the bug report is
			// sguaranteed to be correct.
			// All following instances may be wrong, so we ignore them.
			buildFingerprint = result["build"]
		} else if m, result := historianutils.SubexpNames(modelNameRE, line); m {
			modelName = result["modelName"]
		}
		if deviceID != "" && buildFingerprint != "" && sdkVersion != -1 &&
			modelName != "" {
			break
		}
	}
	if sdkVersion == -1 {
		return nil, errors.New("unable to find device SDK version")
	}
	if deviceID == "" {
		deviceID = "not available"
	}
	if modelName == "" {
		modelName = "unknown device"
	}

	sensors, err := extractSensorInfo(input)

	return &MetaInfo{
		DeviceID:         deviceID,
		SdkVersion:       sdkVersion,
		BuildFingerprint: buildFingerprint,
		ModelName:        modelName,
		Sensors:          sensors,
	}, err
}

// extractSensorInfo extracts device sensor information found in the
// sensorservice dump of a bugreport.
func extractSensorInfo(input string) (map[int32]SensorInfo, error) {
	inSSection := false
	sensors := make(map[int32]SensorInfo)
	curNum := int32(-1)

Loop:
	for _, line := range strings.Split(input, "\n") {
		m, result := historianutils.SubexpNames(historianutils.ServiceDumpRE, line)
		if m {
			switch in := strings.Contains(result["service"], "sensorservice"); {
			case inSSection && !in: // Just exited the section
				break Loop
			case in:
				inSSection = true
				continue Loop
			default: // Random section
				continue Loop
			}
		}
		if !inSSection {
			continue
		}
		// Each sensor's information is captured by one line from MNC or before.
		if m, result := historianutils.SubexpNames(sensorLineMMinusRE, line); m {
			curSensor := SensorInfo{}
			n, err := strconv.ParseInt(result["sensorNumber"], 0, 32)
			if err != nil {
				return nil, err
			}
			curSensor.Number = int32(n)

			v, err := strconv.Atoi(result["versionNumber"])
			if err != nil {
				return nil, err
			}
			curSensor.Version = int32(v)

			// Convert the minRate/maxRate in Hz to maxDelay/minDelay in us.
			if strings.Contains(result["variableOne"], "minRate") {
				if m, rateValResult := historianutils.SubexpNames(rateRE, result["variableOne"]); m {
					rate, err := strconv.ParseFloat(rateValResult["rateVal"], 32)
					if err != nil {
						return nil, err
					}
					curSensor.MaxDelayInUs = historianutils.RoundFloat(
						float64(1000000) / rate)
				}
			} else {
				if m, delayValResult := historianutils.SubexpNames(delayRE, result["variableOne"]); m {
					delay, err := strconv.Atoi(delayValResult["delayVal"])
					if err != nil {
						return nil, err
					}
					curSensor.MaxDelayInUs = int32(delay)
				}
			}
			if strings.Contains(result["variableTwo"], "maxRate") {
				if m, rateValResult := historianutils.SubexpNames(rateRE, result["variableTwo"]); m {
					rate, err := strconv.ParseFloat(rateValResult["rateVal"], 32)
					if err != nil {
						return nil, err
					}
					curSensor.MinDelayInUs = historianutils.RoundFloat(
						float64(1000000) / rate)
				}
			} else {
				if m, delayValResult := historianutils.SubexpNames(delayRE, result["variableTwo"]); m {
					delay, err := strconv.Atoi(delayValResult["delayVal"])
					if err != nil {
						return nil, err
					}
					curSensor.MinDelayInUs = int32(delay)
				}
			}

			wakeup := false
			if x := result["wakeUp"]; x != "non-wakeUp" {
				wakeup = true
			}
			curSensor.WakeUp = wakeup

			curSensor.Batch = false
			if x := result["batching"]; x != "no batching" {
				m, batchingInfo := historianutils.SubexpNames(fifoMaxRE, x)
				if !m {
					continue
				}
				max, err := strconv.Atoi(batchingInfo["maxNum"])
				if err != nil {
					return nil, err
				}
				curSensor.Max = int32(max)
				curSensor.Batch = true
			}

			curSensor.Name = result["sensorName"]
			curSensor.Type = result["sensorTypeString"]
			curSensor.RequestMode = result["requestMode"]
			sensors[int32(n)] = curSensor
			continue
		}

		// Each sensor's information needs at least two lines to record
		// from NRD42 and onwards.
		if line1, result := historianutils.SubexpNames(sensorLine1RE, line); line1 {
			n, err := strconv.ParseInt(result["sensorNumber"], 0, 32)
			if err != nil {
				return nil, err
			}
			curNum = int32(n)

			v, err := strconv.Atoi(result["versionNumber"])
			if err != nil {
				return nil, err
			}

			if _, ok := sensors[curNum]; !ok {
				sensors[curNum] = SensorInfo{}
			}
			curSensor := sensors[curNum]
			curSensor.Name = result["sensorName"]
			curSensor.Number = curNum
			curSensor.Type = result["sensorTypeString"]
			curSensor.Version = int32(v)
			sensors[curNum] = curSensor
		} else if line2, result := historianutils.SubexpNames(sensorLine2RE, line); line2 {
			curSensor := sensors[curNum]
			curSensor.RequestMode = result["requestMode"]

			// Convert the minRate/maxRate in Hz to maxDelay/minDelay in us.
			if strings.Contains(result["variableOne"], "minRate") {
				if m, rateValResult := historianutils.SubexpNames(rateRE, result["variableOne"]); m {
					rate, err := strconv.ParseFloat(rateValResult["rateVal"], 32)
					if err != nil {
						return nil, err
					}
					curSensor.MaxDelayInUs = historianutils.RoundFloat(
						float64(1000000) / rate)
				}
			} else {
				if m, delayValResult := historianutils.SubexpNames(delayRE, result["variableOne"]); m {
					delay, err := strconv.Atoi(delayValResult["delayVal"])
					if err != nil {
						return nil, err
					}
					curSensor.MaxDelayInUs = int32(delay)
				}
			}
			if strings.Contains(result["variableTwo"], "maxRate") {
				if m, rateValResult := historianutils.SubexpNames(rateRE, result["variableTwo"]); m {
					rate, err := strconv.ParseFloat(rateValResult["rateVal"], 32)
					if err != nil {
						return nil, err
					}
					curSensor.MinDelayInUs = historianutils.RoundFloat(
						float64(1000000) / rate)
				}
			} else {
				if m, delayValResult := historianutils.SubexpNames(delayRE, result["variableTwo"]); m {
					delay, err := strconv.Atoi(delayValResult["delayVal"])
					if err != nil {
						return nil, err
					}
					curSensor.MinDelayInUs = int32(delay)
				}
			}

			wakeup := false
			if x := result["wakeUp"]; x != "non-wakeUp" {
				wakeup = true
			}
			curSensor.WakeUp = wakeup

			if x := result["batching"]; x != "no batching" {
				m, batchingInfo := historianutils.SubexpNames(BatchingDataRE, x)
				if !m {
					continue
				}
				max, err := strconv.Atoi(batchingInfo["maxNum"])
				if err != nil {
					return nil, err
				}
				reserved, err := strconv.Atoi(batchingInfo["reservedNum"])
				if err != nil {
					return nil, err
				}
				curSensor.Batch = true
				curSensor.Max = int32(max)
				curSensor.Reserved = int32(reserved)
			}
			sensors[curNum] = curSensor
			curNum = int32(-1)
		} else {
			continue
		}
	}

	sensors[GPSSensorNumber] = SensorInfo{
		Name:   "GPS",
		Number: GPSSensorNumber,
	}

	return sensors, nil
}

// ExtractBatterystatsCheckin extracts and returns only the lines in
// input that are included in the "CHECKIN BATTERYSTATS" section.
func ExtractBatterystatsCheckin(input string) string {
	inBsSection := false
	var bsCheckin []string

Loop:
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if m, result := historianutils.SubexpNames(BugReportSectionRE, line); m {
			switch in := strings.Contains(result["section"],
				"CHECKIN BATTERYSTATS"); {
			case inBsSection && !in: // Just exited the section
				break Loop
			case in:
				inBsSection = true
				continue Loop
			default: // Random section
				continue Loop
			}
		}
		if inBsSection {
			bsCheckin = append(bsCheckin, line)
		}
	}

	return strings.Join(bsCheckin, "\n")
}

// ExtractBugReport extracts and returns only the first valid bug report data
// in the given contents. The second returned parameter will be the determined
// file name.
func ExtractBugReport(fname string, contents []byte) (string, string, error) {
	fs, err := Contents(fname, contents)
	if err != nil {
		return "", "", err
	}
	for n, f := range fs {
		if IsBugReport(f) {
			return string(f), n, nil
		}
	}
	return "", "", fmt.Errorf("%s did not contain a valid bug report", fname)
}

// AppInfo holds the name and UID for an app.
type AppInfo struct {
	Name string
	UID  string
}

// ExtractPIDMappings returns mappings from PID to app names and UIDs
// extracted from the bug report.
func ExtractPIDMappings(contents string) (map[string][]AppInfo, []string) {
	var warnings []string
	mapping := make(map[string][]AppInfo)
	for _, line := range strings.Split(contents, "\n") {
		if m, result := historianutils.SubexpNames(pidRE, line); m {
			baseUID, err := packageutils.AppIDFromString(result["uid"])
			uidStr := strconv.Itoa(int(baseUID))
			if err != nil {
				uidStr = ""
				warnings = append(warnings,
					fmt.Sprintf("invalid uid: %s", result["uid"]))
			}
			mapping[result["pid"]] = append(mapping[result["pid"]], AppInfo{
				Name: result["app"],
				UID:  uidStr,
			})
		}
	}
	return mapping, warnings
}

// TimeStampToMs converts a timestamp in the TimeLayout format, combined with
// the fraction of a second, to a unix ms timestamp based on the location.
func TimeStampToMs(timestamp, remainder string, loc *time.Location) (int64, error) {
	if loc == nil {
		return 0, errors.New("missing location")
	}
	t, err := time.ParseInLocation(TimeLayout, timestamp, loc)
	if err != nil {
		return 0, err
	}
	// The remainder represents the fraction of a second.
	// e.g. timestamp 2015-05-28 19:50:27.123456 has remainder 123456.
	ms, err := SecFractionAsMs(remainder)
	if err != nil {
		return 0, err
	}
	return ((t.Unix() * 1000) + ms), nil
}

// SecFractionAsMs converts the fraction of a second to milliseconds.
// e.g. "123456" from "27.123456" corresponds to 123ms (and 27 seconds).
func SecFractionAsMs(fr string) (int64, error) {
	// The string will be parsed as ms, so only the leading 3 digits of the
	// string are used.
	// Make sure the remainder has at least 3 digits, so the slice operation
	// doesn't fail.
	fr = fmt.Sprintf("%s000", fr)
	// Truncate to 3 decimal points.
	ms := fr[:3]
	return strconv.ParseInt(ms, 10, 64)
}

// TimeZone extracts the time zone from a bug report.
func TimeZone(contents string) (*time.Location, error) {
	for _, line := range strings.Split(contents, "\n") {
		if m, result := historianutils.SubexpNames(TimeZoneRE, line); m {
			return time.LoadLocation(result["timezone"])
		}
	}
	// If the timezone was missing, it's likely the phone was just reset and
	// everything is in UTC time.
	fmt.Println("missing time zone line in bug report")
	return time.UTC, nil
}

// DumpState returns the parsed dumpstate information as a time object.
func DumpState(contents string) (time.Time, error) {
	loc, err := TimeZone(contents)
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(contents, "\n") {
		if m, result := historianutils.SubexpNames(DumpstateRE, line); m {
			d, err := time.ParseInLocation(TimeLayout,
				strings.TrimSpace(result["timestamp"]), loc)
			if err != nil {
				return time.Time{}, err
			}
			return d, nil
		}
	}
	return time.Time{},
		errors.New("could not find dumpstate information in bugreport")
}
