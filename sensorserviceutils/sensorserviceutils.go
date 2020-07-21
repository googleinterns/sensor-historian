// Copyright 2020 Google LLC. All Rights Reserved.
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

// Package sensorserviceutils is a library of common functions for
// parsing sensorservice dump.
// The feature is only available for Android version Q and onwards.
package sensorserviceutils

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/googleinterns/sensor-historian/bugreportutils"
	"github.com/googleinterns/sensor-historian/csv"
	"github.com/googleinterns/sensor-historian/historianutils"
	sipb "github.com/googleinterns/sensor-historian/pb/sensorsinfo_proto"
)

var (
	// Each of the connLineXRE is a regular expression to match the X line of
	// connection information in the sensorservice dump in the bugreport.
	// Active connection information has the same format for all Android versions.
	connLine1RE = regexp.MustCompile(`\s*Connection\s+Number:\s*` +
		`(?P<connNum>\d+)`)
	connLine2RE = regexp.MustCompile(`\s*Operating\s+Mode:` +
		`(?P<connMode>[^(]+)` + `\s*`)
	connLine3RE = regexp.MustCompile(`\s*(?P<packageName>[^(]+)` +
		`\s*\|\s*` + `WakeLockRefCount\s*(?P<wakeLockRefCount>\d+)` +
		`\s*\|\s*` + `uid\s*(?P<uid>\d+)`)
	connLine4RE = regexp.MustCompile(`(?P<sensorNumber>0x?[0-9A-Fa-f]+)` +
		`\s*\|\s*` + `status:\s*(?P<status>[^(]+)` + `\s*\|\s*` +
		`pending\s*flush\s*events\s*` + `(?P<pendingFlush>\d+)`)

	// sensorListRE is a regular expression to match the section for all
	// sensors' information in the sensorservice dump in the bugreport
	sensorListRE = regexp.MustCompile(`\s*Sensor\s*List:\s*`)

	// sensorActiveLineRE is a regular expression to match header of
	// the section for all active sensors' information in the
	// sensorservice dump in the bugreport.
	sensorActiveLineRE = regexp.MustCompile(`Total\s*` + `(?P<total>\d+)` +
		`\s*h/w sensors,\s*` + `(?P<running>\d+)` + `\s*running:`)

	// activeSensorRE is a regular expression to match the line for active
	// sensor's information in the sensorservice dump in the bugreport.
	activeSensorRE = regexp.MustCompile(`(?P<sensorNumber>0x?[0-9A-Fa-f]+)\)` +
		`.*` + `selected = (?P<samplingPeriodMs>[0-9]*\.?[0-9]+) ms;` + `.*` +
		`selected = (?P<batchingPeriodMs>[0-9]*\.?[0-9]+) ms`)

	// activeConnRE is a regular expression to match the section for active
	// connections in the sensorservice dump in the bugreport
	// for all Android version.
	activeConnRE = regexp.MustCompile(`\s*active\s*connections\s*`)

	// directConnRE is a regular expression to match the section for direct
	// connections in the sensorservice dump in the bugreport
	// for all Android version.
	directConnRE = regexp.MustCompile(`\s*direct\s*connections\s*`)

	// prevRegistrationRE is a regular expression to match the section for
	// previous connections in the sensorservice dump in the bugreport
	// for all Android version.
	prevRegistrationRE = regexp.MustCompile(`Previous\s*Registrations:`)

	// addRegistrationRE is a regular expression to match the log that adds
	// subscription in the sensorservice dump in the bugreport
	// for Android starting from NRD42 and onwards.
	addRegistrationRE = regexp.MustCompile(`(?P<time>\d+\:\d+\:\d+)\s*` +
		`\+` + `\s*(?P<sensorNumber>0x?[0-9A-Fa-f]+)` + `\s*pid=\s*` +
		`(?P<pid>\d+)` + `\s*uid=\s*` + `(?P<uid>\d+)` + `\s*package=\s*` +
		`(?P<packageName>[^(]+)` + `\s*samplingPeriod=\s*` +
		`(?P<samplingPeriodUs>\d+)us` + `\s*batchingPeriod=\s*` +
		`(?P<batchingPeriodUs>\d+)us`)

	// removeRegistrationRE is a regular expression to match the log that
	// removes subscription in the sensorservice dump in the bugreport
	// for Android starting from NRD42 and onwards.
	removeRegistrationRE = regexp.MustCompile(`(?P<time>\d+\:\d+\:\d+)` +
		`\s*` + `\-` + `\s*(?P<sensorNumber>0x?[0-9A-Fa-f]+)` + `\s*pid=\s*` +
		`(?P<pid>\d+)` + `\s*uid=\s*` + `(?P<uid>\d+)` + `\s*package=\s*` +
		`(?P<packageName>[^(]+)`)

	// timeLayoutRE is a regular expression to match the time information with
	// dates that may show up in the bugreport.
	timeLayoutRE = regexp.MustCompile(`^(?P<month>\d+)\-(?P<day>\d+)`)
)

const (
	timeFormat      = "15:04:05"
	sensorRegisDesc = "Sensorservice Registration"
	parseConnErrStr = "Parse Active Conn"
	parseRegErrStr  = "Parse Registration"
	sensorDump      = "Sensorservice Dump"
)

// OutputData contains information for active connection and previous
// registration history collected in the sensorservice dump.
type OutputData struct {
	CSV         string
	SensorInfo  *sipb.AllSensorsInfo
	ParsingErrs []error
	SensorErrs  []error
}

// activeSensor contains information about an active sensor. All relevant
// information comes from the active sensor section in the sensorservice dump.
type activeSensor struct {
	sensorNumber    int32
	samplingRateHz  float64
	batchingPeriodS float64
}

type parser struct {
	// referenceYear is the year extracted from the dumpstate line in bugreport.
	// Previous Registration lines don't contain a year in the date string,
	// so we use this to reconstruct the full timestamp.
	referenceYear int

	// referenceMonth is the month extracted from the dumpstate line in bugreport.
	// Since a bugreport may span over a year boundary, we use the month to
	// check whether the year for the event needs to be decremented
	// or incremented.
	referenceMonth int

	// referenceDay is the month extracted from the dumpstate line in bugreport.
	referenceDay int

	// currentTime is the time extracted from the dumpstate line in a bugreport.
	// It is in the traditional HH:MM:SS format.
	referenceTime string

	// earliestTimestampMs is the timestamp corresponding to the last event
	// recorded in the Previous Registration section.
	// If there is no previous registration section, earliestTimestampMs is
	// set to be the timestamp in Ms for the referenceTime.
	earliestTimestampMs int64

	// loc is the location parsed from timezone information in the bugreport.
	// The previous registration is in the user's local timezone
	// which we need to convert to UTC time.
	loc         *time.Location
	lines       []string
	idx         int
	buf         *bytes.Buffer
	csvState    *csv.State
	parsingErrs []error
	sensorErrs  []error

	// sensors is a map from sensor number to the relevant sensor's information.
	sensors map[int32]*sipb.Sensor

	// activeSensors is a map from sensor number to the relevant sensor's
	// information. This map only contains information for active sensors.
	activeSensors map[int32]activeSensor

	// activeConns is a map from an identifier to the relevant connection
	// information.
	// If a sensor is actively subscribed by a package when the bugreport is
	// generated, the relevant connection information can be obtained using
	// an identifier formed by concatenating sensor number and package name.
	activeConns map[string]*sipb.ActiveConn

	// history is a map from an identifier to an sensor subscription event.
	// Note that the identifier is a string formed by concatenating
	// sensor number and name of the package that subscribes the sensor.
	history map[string]*sipb.SubscriptionInfo
}

// Returns the current line without advancing the line position.
func (p *parser) peek() string {
	if p.valid() {
		return p.lines[p.idx]
	}
	return ""
}

// Returns the current line and advances the line position.
func (p *parser) line() string {
	if !p.valid() {
		return ""
	}
	l := p.lines[p.idx]
	p.idx++
	return l
}

// Returns the previous line and move to that line position.
func (p *parser) prevline() string {
	if !p.valid() {
		return ""
	}
	if p.idx <= 0 {
		return ""
	}
	p.idx--
	l := p.lines[p.idx]
	return l
}

// Returns whether the current line position corresponds to a valid line.
func (p *parser) valid() bool {
	return (p.idx < len(p.lines)) && (p.idx >= 0)
}

// Parse function collects information regarding active connections and
// records availalbe sensor subscription events in the sensorservice section
// as CSV entry.
// Errors encountered during parsing and potential errors for sensor activities
// will be collected into an errors slice.
// The parser will continue parsing remaining events.
func Parse(f string, meta *bugreportutils.MetaInfo) OutputData {
	loc, err := bugreportutils.TimeZone(f)
	if err != nil {
		parseErr := []error{fmt.Errorf(
			"Parse Time Zone: missing time zone line in bug report : %s", err)}
		return OutputData{"", nil, parseErr, nil}
	}

	// Extract the date and time from the bugreport dumpstate line.
	d, err := bugreportutils.DumpState(f)
	if err != nil {
		parseErr := []error{
			fmt.Errorf("Parse Dumpstate: could not find dumpstate " +
				"information in the bugreport")}
		return OutputData{"", nil, parseErr, nil}
	}

	buf := new(bytes.Buffer)
	p := &parser{
		referenceYear:  d.Year(),
		referenceMonth: int(d.Month()),
		referenceDay:   d.Day(),
		referenceTime:  d.Format(timeFormat),
		loc:            loc,
		buf:            buf,
		csvState:       csv.NewState(buf, true),
		lines:          strings.Split(f, "\n"),
		activeSensors:  make(map[int32]activeSensor),
		activeConns:    make(map[string]*sipb.ActiveConn),
		history:        make(map[string]*sipb.SubscriptionInfo),
		sensors:        make(map[int32]*sipb.Sensor),
	}
	p.updateSensorsInfo(meta.Sensors)
	referenceTimestampMs, _ := p.fullTimestampInMs(p.referenceMonth,
		p.referenceDay, p.referenceTime)
	p.earliestTimestampMs = referenceTimestampMs

	for p.valid() {
		l := p.line() // Read the current line and advance the line position.
		// Parse active sensor information.
		if m, _ := historianutils.SubexpNames(sensorActiveLineRE, l); m {
			p.parsingErrs, p.sensorErrs = p.extractActiveSensorInfo()
			continue
		}
		// Parse active connection information.
		if m, _ := historianutils.SubexpNames(activeConnRE, l); m {
			p.parsingErrs, p.sensorErrs = p.extractActiveConnInfo()
			continue
		}
		// Parse registration history information
		if m, _ := historianutils.SubexpNames(prevRegistrationRE, l); m {
			p.parsingErrs, p.sensorErrs = p.extractRegistrationHistory()
			continue
		}
	}
	p.creatUnseenActiveConnectionHistory()

	return OutputData{p.buf.String(), p.allSensorInfo(),
		p.parsingErrs, p.sensorErrs}
}

func constructSensorName(nameStr, typeStr string, number int32) string {
	var newName string
	typeMap := strings.Split(typeStr, ".")
	if number != -1 {
		// There are sensors with the same name and type, add sensor number
		// to its name.
		newName = fmt.Sprintf("%d.%s (%s)",
			number, nameStr, typeMap[len(typeMap)-1])
	} else {
		newName = fmt.Sprintf("%s (%s)", nameStr, typeMap[len(typeMap)-1])
	}
	return newName
}

func (p parser) updateSensorsInfo(sensors map[int32]bugreportutils.SensorInfo) {
	sensorCheck := make(map[string][]int32, len(sensors))
	for curNum, sensorInfo := range sensors {
		curSensorName := sensorInfo.Name
		conflictName := sensorInfo.Name
		if oldNums, exist := sensorCheck[curSensorName]; exist {
			// Check for sensors that share the same name.
			// If a collision exists, rename the sensor to include its type and
			// sensor number if necessary
			// e.g. consider the following three sensors, they are renamed to:
			// 0x00000007 nameA typeA --> 7) nameA (typeA)
			// 0x00000008 nameA typeB --> nameA (typeB)
			// 0x00000009 nameA typeA --> 9) nameA(typeA)
			curType := sensorInfo.Type
			newNameHasNum := false
			for _, oldNum := range oldNums {
				oldType := p.sensors[oldNum].Type
				oldSensorName := p.sensors[oldNum].Name
				oldNameHasNum := strings.Contains(oldSensorName, ".")
				if newNameHasNum != true {
					// Once the name includes the sensor number, it is for sure
					// a unique name since no two sensors should have the same
					// number.
					if curType == oldType {
						newNameHasNum = true
						curSensorName = constructSensorName(conflictName,
							curType, curNum)
					} else {
						curSensorName = constructSensorName(conflictName,
							curType, -1)
					}
				}
				if !oldNameHasNum {
					if curType == oldType {
						oldSensorName = constructSensorName(conflictName,
							oldType, oldNum)
					} else {
						oldSensorName = constructSensorName(conflictName,
							oldType, -1)
					}
				}
				p.sensors[oldNum].Name = oldSensorName
			}
		} else {
			collision := make([]int32, 0)
			sensorCheck[curSensorName] = collision
		}
		collisions := sensorCheck[conflictName]
		collisions = append(collisions, curNum)
		sensorCheck[conflictName] = collisions
		sensor := &sipb.Sensor{
			Name:          curSensorName,
			Type:          sensorInfo.Type,
			Version:       sensorInfo.Version,
			Number:        sensorInfo.Number,
			RequestMode:   sipb.RequestMode(sensorInfo.RequestMode),
			MaxRateHz:     sensorInfo.MaxRateHz,
			MinRateHz:     sensorInfo.MinRateHz,
			Batch:         sensorInfo.Batch,
			Max:           sensorInfo.Max,
			Reserved:      sensorInfo.Reserved,
			WakeUp:        sensorInfo.WakeUp,
			Subscriptions: make([]*sipb.SubscriptionInfo, 1),
			ActiveConns:   make([]*sipb.ActiveConn, 1),
		}
		p.sensors[curNum] = sensor
	}
}

// To sort sensor information by sensor number, the following interface is used.
type sensors []*sipb.Sensor

func (slice sensors) Len() int {
	return len(slice)
}
func (slice sensors) Less(i, j int) bool {
	return slice[i].Number < slice[j].Number
}
func (slice sensors) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (p parser) allSensorInfo() *sipb.AllSensorsInfo {
	allActiveConns := make(activeConns, 0, len(p.activeConns))
	for _, conn := range p.activeConns {
		allActiveConns = append(allActiveConns, conn)
	}
	sort.Sort(allActiveConns)

	allSensors := make(sensors, 0, len(p.sensors))
	for _, sensorInfo := range p.sensors {
		allSensors = append(allSensors, sensorInfo)
	}
	sort.Sort(allSensors)

	return &sipb.AllSensorsInfo{
		AllActiveConns: allActiveConns,
		Sensors:        allSensors,
		Apps:           nil,
	}
}

// extractActiveConnInfo extracts information for active sensors found in
// the sensorservice dump of a bugreport.
func (p parser) extractActiveSensorInfo() ([]error, []error) {
	for p.valid() {
		line := p.line()
		// Stop when reaching the Sensor List sections.
		if m, _ := historianutils.SubexpNames(sensorListRE, line); m {
			break
		}
		if m, result := historianutils.SubexpNames(activeSensorRE, line); m {
			n, err := strconv.ParseInt(result["sensorNumber"], 0, 32)
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("[Active Sensor]: error parsing sensor number "+
						"%v for line %v:%v", result["sensorNumber"], line, err))
				continue
			}
			sensorNumber := int32(n)
			sPeriodMs, err := strconv.ParseFloat(result["samplingPeriodMs"], 64)
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("[Active Sensor] sensor(%v): error parsing "+
						"sampling period %v for line %v:%v", sensorNumber,
						result["samplingPeriodMs"], line, err))
				continue
			}
			bPeriodMs, err := strconv.ParseFloat(result["batchingPeriodMs"], 64)
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("[Active Sensor] sensor(%v): error parsing "+
						"batching period %v for line %v:%v", sensorNumber,
						result["batchingPeriodMs"], line, err))
				continue
			}
			samplingPeriodUs := int(sPeriodMs * 1000)
			samplingRateHz := historianutils.PeriodUsToRateHz(samplingPeriodUs)
			batchingPeriodS := math.Round(bPeriodMs*0.1) / 100
			p.activeSensors[sensorNumber] = activeSensor{
				sensorNumber:    sensorNumber,
				samplingRateHz:  samplingRateHz,
				batchingPeriodS: batchingPeriodS,
			}
		}
	}
	return p.parsingErrs, p.sensorErrs
}

// extractActiveConnInfo extracts active connections information found in
// the sensorservice dump of a bugreport.
func (p parser) extractActiveConnInfo() ([]error, []error) {
	curConnNum := int32(-1)
	// connections is a map from active connection number to
	// information for the relevant connection.
	connections := make(map[int32]*sipb.ActiveConn)

	for p.valid() {
		line := p.line()
		// Stop when reaching the section about direct connection.
		if m, _ := historianutils.SubexpNames(directConnRE, line); m {
			p.prevline()
			break
		}
		// In Android MNC or before, the direct connesction section may not
		// exist if there is no direct connections.
		// The section stops when reaching the previous registration section.
		if m, _ := historianutils.SubexpNames(prevRegistrationRE, line); m {
			p.prevline()
			break
		}
		// For all Android version: each active connection's information needs
		// four lines to record.
		if l1, result := historianutils.SubexpNames(connLine1RE, line); l1 {
			connNum, err := strconv.Atoi(result["connNum"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("%s: error parsing connection number %v:%v",
						parseConnErrStr, result["connNum"], err))
				continue
			}
			// Since proto buff restricts that field numbers must be positive
			// integers, we will not use zero-indexing by adding 1 to
			// all connection number.
			curConnNum = int32(connNum) + 1
			if _, ok := connections[curConnNum]; !ok {
				connections[curConnNum] = &sipb.ActiveConn{
					Number:                 curConnNum,
					OperatingMode:          ``,
					PackageName:            ``,
					UID:                    -1,
					SensorNumber:           -1,
					PendingFlush:           -1,
					SamplingRateHz:         -1,
					BatchingPeriodS:        -1,
					HasSensorserviceRecord: false,
					Source:                 sensorDump,
				}
			}
		} else {
			_, ok := connections[curConnNum]
			if !ok {
				p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
					"%s: connection(%d): no information for this connection",
					parseConnErrStr, curConnNum))
				continue
			}
			if l2, result := historianutils.SubexpNames(connLine2RE, line); l2 {
				connections[curConnNum].OperatingMode = result["connMode"]
			} else if l3, result := historianutils.SubexpNames(connLine3RE, line); l3 {
				uid, err := strconv.Atoi(result["uid"])
				if err != nil {
					p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
						"%s: connection(%d): error parsing uid %v:%v",
						parseConnErrStr, curConnNum, result["uid"], err))
					continue
				}
				connections[curConnNum].UID = int32(uid)
				connections[curConnNum].PackageName = result["packageName"]
			} else if l4, result := historianutils.SubexpNames(connLine4RE, line); l4 {
				n, err := strconv.ParseInt(result["sensorNumber"], 0, 32)
				if err != nil {
					p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
						"%s: connection(%d): error parsing sensorNumber %v:%v",
						parseConnErrStr, curConnNum, result["sensorNumber"],
						err))
					continue
				}
				sensorNumber := int32(n)
				connections[curConnNum].SensorNumber = sensorNumber
				pendingFlush, err := strconv.Atoi(result["pendingFlush"])
				if err != nil {
					p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
						"%s: connection(%d): error parsing pendingFlush %v:%v",
						parseConnErrStr, curConnNum, result["pendingFlush"],
						err))
					continue
				}
				connections[curConnNum].PendingFlush = int32(pendingFlush)
				if activeSensor, exist := p.activeSensors[sensorNumber]; exist {
					connections[curConnNum].SamplingRateHz =
						activeSensor.samplingRateHz
					connections[curConnNum].BatchingPeriodS =
						activeSensor.batchingPeriodS
				} else {
					p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
						"[Active Connection]: connection(%d): the sensor(%d)"+
							" is not active according to the sensor device"+
							" section", curConnNum, sensorNumber))
					continue
				}
			}
		}
	}

	// Build the new map that uses identifier to look up relevant active
	// connection information.
	for _, conn := range connections {
		identifier := fmt.Sprintf("%d,%s", conn.SensorNumber, conn.PackageName)
		p.activeConns[identifier] = conn
	}
	return p.parsingErrs, p.sensorErrs
}

// extractRegistrationHistory extracts all previous registration information
// found in the sensorservice dump of a bug report.
// Note that the previous registration history records the subscription event
// in reverse chronological order.
func (p *parser) extractRegistrationHistory() ([]error, []error) {
	referenceTimestampMs, _ := p.fullTimestampInMs(p.referenceMonth,
		p.referenceDay, p.referenceTime)
	for p.valid() {
		l := p.line()
		var result map[string]string
		isAdd := false
		if m, match := historianutils.SubexpNames(addRegistrationRE, l); m {
			result = match
			isAdd = true
		} else if m, match := historianutils.SubexpNames(removeRegistrationRE, l); m {
			result = match
		} else {
			// Reach the end of the registration section.
			break
		}

		// Get the time of the record.
		// Accomodate the case where the time information includes date.
		hasDate, date := historianutils.SubexpNames(timeLayoutRE, l)
		var timestampMs int64
		var timestampErr error
		if hasDate {
			month, err := strconv.Atoi(date["month"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("%s: error parsing month information for "+
						"line %v: %v", parseRegErrStr, l, timestampErr))
				continue
			}
			day, err := strconv.Atoi(date["day"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("%s: error parsing day information for "+
						"line %v: %v", parseRegErrStr, l, timestampErr))
				continue
			}
			timestampMs, timestampErr = p.fullTimestampInMs(month, day,
				result["time"])
		} else {
			timestampMs, timestampErr = p.fullTimestampInMs(p.referenceMonth,
				p.referenceDay, result["time"])
		}
		if timestampErr != nil {
			p.parsingErrs = append(p.parsingErrs,
				fmt.Errorf("%s: error parsing time information for line %v: %v",
					parseRegErrStr, l, timestampErr))
			continue
		}
		if p.earliestTimestampMs > timestampMs {
			p.earliestTimestampMs = timestampMs
		}

		// All registration history records information for
		// sensorNumber, uid, and packageName.
		handle, err := strconv.ParseInt(result["sensorNumber"], 0, 32)
		if err != nil {
			p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
				"%s: error parsing sensorNumber %v for line %v: %v",
				parseRegErrStr, result["sensorNumber"], l, err))
			continue
		}
		sensorNumber := int32(handle)
		_, exist := p.sensors[sensorNumber]
		if !exist {
			p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
				"[Sensor Error]: sensor %d: invalid subscription for an "+
					"non-existing sensor", sensorNumber))
			continue
		}
		packageName := result["packageName"]
		uid, err := strconv.Atoi(result["uid"])
		if err != nil {
			p.parsingErrs = append(p.parsingErrs,
				fmt.Errorf("%s: error parsing uid %v for line %v: %v",
					parseRegErrStr, result["uid"], l, err))
			continue
		}
		identifier := fmt.Sprintf("%d,%s", sensorNumber, packageName)

		if isAdd {
			// Currently processing an activated statement.
			samplingPeriodUs, err := strconv.Atoi(result["samplingPeriodUs"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
					"%s: error parsing samplingPeriod %v us for line %v: %v",
					parseRegErrStr, result["samplingPeriodUs"], l, err))
				continue
			}
			batchingPeriodUs, err := strconv.Atoi(result["batchingPeriodUs"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
					"%s: error parsing batchingPeriod %v us for line %v: %v",
					parseRegErrStr, result["batchingPeriodUs"], l, err))
				continue
			}
			samplingRateHz := historianutils.PeriodUsToRateHz(samplingPeriodUs)
			batchingPeriodS := math.Round(float64(batchingPeriodUs)*1e-04) / 100
			_, exist := p.history[identifier]
			if !exist {
				// If there is no history of de-activating a subscription,
				// the subscription has to be active.
				if conn, isActive := p.activeConns[identifier]; isActive {
					// For active connection, set current time as the end time
					// for the ongoing subscription event.
					sensorName := p.sensors[sensorNumber].Name
					if samplingRateHz != conn.SamplingRateHz {
						p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
							"[Active Sensor]: active connection for pkg(%s) "+
								"and sensor(%d) shows two sampling rate(Hz):"+
								" %.2f at active sensor section; %.2f at "+
								"history section", packageName, sensorNumber,
							conn.SamplingRateHz, samplingRateHz))
						if conn.SamplingRateHz == -1 {
							p.activeConns[identifier].SamplingRateHz =
								samplingRateHz
						}
					}
					if batchingPeriodS != conn.BatchingPeriodS {
						p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
							"[Active Sensor]: active connection for pkg(%s) "+
								"and sensor(%d) shows two batching period(s):"+
								" %.2f at active sensor section; %.2f at "+
								"history section", packageName, sensorNumber,
							conn.BatchingPeriodS, batchingPeriodS))
						if conn.BatchingPeriodS == -1 {
							p.activeConns[identifier].BatchingPeriodS =
								batchingPeriodS
						}
					}

					start := msToTime(timestampMs).In(p.loc).Format(timeFormat)
					end := msToTime(referenceTimestampMs).In(p.loc).Format(timeFormat)
					value := fmt.Sprintf("%v,%v,%d,%s,%d,%s,%.2f,%.2f,%s,%s", start,
						end, sensorNumber, p.sensors[sensorNumber].RequestMode,
						uid, packageName, samplingRateHz, batchingPeriodS,
						sensorDump, "isActiveConn")

					p.csvState.Print(sensorName, "string", timestampMs,
						referenceTimestampMs, value, "")
					conn.HasSensorserviceRecord = true
					p.activeConns[identifier] = conn
				} else {
					p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
						"[Invalid Activation]: connection between pkg(%s) "+
							"and sensor(%d) should be active", packageName,
						sensorNumber))
				}
			} else {
				// A de-activation statement for the subscription event is seen.
				eventInfo := p.history[identifier]
				if eventInfo.StartMs != -1 {
					// A previous de-activation statement for this connection
					// has paired up with an activation statement. The current
					// activation statement is an extra one.
					p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
						"[Multiple Activation]: for pkg(%s) and sensor(%d)",
						packageName, sensorNumber))
				} else {
					// The current activation statement can pair up with a
					// previous de-activation statement to complete a
					// subscription event.
					eventInfo.StartMs = timestampMs
					eventInfo.SamplingRateHz = samplingRateHz
					eventInfo.BatchingPeriodS = batchingPeriodS
					sensorName := p.sensors[sensorNumber].Name
					start := msToTime(timestampMs).In(p.loc).Format(timeFormat)
					end := msToTime(eventInfo.EndMs).In(p.loc).Format(timeFormat)
					value := fmt.Sprintf("%v,%v,%d,%s,%d,%s,%.2f,%.2f,%s", start,
						end, sensorNumber, p.sensors[sensorNumber].RequestMode,
						uid, packageName, samplingRateHz, batchingPeriodS,
						sensorDump)
					p.csvState.Print(sensorName, "string",
						timestampMs, eventInfo.EndMs, value, "")
				}
			}
		} else {
			// Currently processing a de-activation statement.
			if event, exist := p.history[identifier]; exist {
				if event.StartMs == -1 {
					p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
						"[Multiple De-Activation]: for pkg(%s) and sensor(%d)",
						packageName, sensorNumber))
				} else {
					// Current de-activation statement will be counted as
					// a new subscription event.
					eventInfo := &sipb.SubscriptionInfo{
						StartMs:      -1,
						EndMs:        timestampMs,
						SensorNumber: sensorNumber,
						PackageName:  packageName,
						Source:       sensorDump,
					}
					p.history[identifier] = eventInfo
				}
			} else {
				eventInfo := &sipb.SubscriptionInfo{
					StartMs:      -1,
					EndMs:        timestampMs,
					SensorNumber: sensorNumber,
					PackageName:  packageName,
					Source:       sensorDump,
				}
				p.history[identifier] = eventInfo
			}
		}
	}

	return p.parsingErrs, p.sensorErrs
}

// To sort the active connection information, the following interface is used.
type activeConns []*sipb.ActiveConn

func (slice activeConns) Len() int {
	return len(slice)
}

func (slice activeConns) Less(i, j int) bool {
	return slice[i].Number < slice[j].Number
}

func (slice activeConns) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (p parser) creatUnseenActiveConnectionHistory() {
	referenceTimestampMs, _ := p.fullTimestampInMs(p.referenceMonth,
		p.referenceDay, p.referenceTime)

	// Store all the active connections without history in a list and order
	// the list by the connection number.
	connNoHistory := make(activeConns, 0, len(p.activeConns))
	for _, conn := range p.activeConns {
		if !conn.HasSensorserviceRecord {
			connNoHistory = append(connNoHistory, conn)
		}
	}
	sort.Sort(connNoHistory)

	for _, conn := range connNoHistory {
		start := msToTime(p.earliestTimestampMs).In(p.loc).Format(timeFormat)
		end := msToTime(referenceTimestampMs).In(p.loc).Format(timeFormat)
		samplingRateHz := conn.SamplingRateHz
		batchingPeriodS := conn.BatchingPeriodS
		value := fmt.Sprintf("%v,%v,%d,%s,%d,%s,%.2f,%.2f,%s,%s", start, end,
			conn.SensorNumber, p.sensors[conn.SensorNumber].RequestMode,
			conn.UID, conn.PackageName, samplingRateHz,
			batchingPeriodS, conn.Source, "isActiveConn")
		sensorName := p.sensors[conn.SensorNumber].Name
		p.csvState.Print(sensorName, "string", p.earliestTimestampMs,
			referenceTimestampMs, value, "")
	}
}

func validMonth(m int) bool {
	return m >= int(time.January) && m <= int(time.December)
}

// fullTimestampInMs constructs the unix ms timestamp from the given date and
// time information.
// Since previous registration events have no corresponding year,
// we reconstruct the full timestamp using the stored reference year and
// month extracted from the dumpstate line of the bug report.
func (p *parser) fullTimestampInMs(month, day int, partialTimestamp string) (int64, error) {
	remainder := "000"
	if !validMonth(month) {
		return 0, fmt.Errorf("invalid month: %d", month)
	}
	year := p.referenceYear
	// The reference month and year represents the time the bugreport was taken.
	// Since events do not have the year and may be out of order, we guess the
	// year based on the month the event occurred and the reference month.
	//
	// If the event's month was greater than the reference month by a lot, the
	// event is assumed to have taken place in the year preceding the reference
	// year since it doesn't make sense for events to exist so long after
	// the bugreport was taken.
	// e.g. Reference date: March 2016,
	//		Event month: October,
	// 		year assumed to be 2015.
	//
	// If the bug report event log begins near the end of a year, and rolls over
	// to the next year, the event would have taken place in the year preceding
	// the reference year.
	if p.referenceMonth-month < -1 {
		year--
		// Some events may still occur after the given reference date,
		// so we check for a year rollover in the other direction.
	} else if p.referenceMonth == 12 && month == 1 {
		year++
	}

	monStr := strconv.Itoa(month)
	dayStr := strconv.Itoa(day)
	if month < 10 {
		monStr = fmt.Sprintf("0%d", month)
	}
	if day < 10 {
		dayStr = fmt.Sprintf("0%d", day)
	}

	return bugreportutils.TimeStampToMs(
		fmt.Sprintf("%d-%s-%s %s", year, monStr, dayStr, partialTimestamp),
		remainder, p.loc)
}

// msToTime converts milliseconds since Unix Epoch to a time.Time object.
func msToTime(ms int64) time.Time {
	return time.Unix(0, ms*int64(time.Millisecond))
}
