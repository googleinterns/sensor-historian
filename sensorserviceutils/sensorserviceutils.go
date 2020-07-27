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
	// Each of the actConnLineXRE is a regular expression to match the X line of
	// active connection information in the sensorservice dump in the bugreport.
	// Active connection information has the same format for all Android versions.
	actConnLine1RE = regexp.MustCompile(`\s*Connection\s+Number:\s*` +
		`(?P<connNum>\d+)`)
	actConnLine2RE = regexp.MustCompile(`\s*Operating\s+Mode:` +
		`(?P<connMode>[^(]+)` + `\s*`)
	actConnLine3RE = regexp.MustCompile(`\s*(?P<packageName>[^(]+)` +
		`\s*\|\s*` + `WakeLockRefCount\s*(?P<wakeLockRefCount>\d+)` +
		`\s*\|\s*` + `uid\s*(?P<uid>\d+)`)
	actConnLine4RE = regexp.MustCompile(`(?P<sensorNumber>0x?[0-9A-Fa-f]+)` +
		`\s*\|\s*` + `status:\s*(?P<status>[^(]+)` + `\s*\|\s*` +
		`pending\s*flush\s*events\s*` + `(?P<pendingFlush>\d+)`)

	// Each of the dirConnLineXRE is a regular expression to match the X line of
	// direct connection information in the sensorservice dump in the bugreport.
	dirConnLine1RE = regexp.MustCompile(`\s*Direct\s+connection\s*` +
		`(?P<connNum>\d+)`)
	dirConnLine2RE = regexp.MustCompile(`Package\s*(?P<packageName>[^(^,]+),` +
		`\s*HAL\s*channel\s*handle (?P<halHandle>\d+)`)
	dirConnLine3RE = regexp.MustCompile(`\s*Sensor\s*` +
		`(?P<sensorNumber>0x?[0-9A-Fa-f]+)` + `\,\s*rate\s*` +
		`(?P<rateLevel>\d+)`)

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

	// directConns is a map from an identifier to the relevant connection
	// information.
	directConns map[string]*sipb.DirectConn

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
	// Sensor historian only supports andriod sdk version 26 and onwards.
	if meta.SdkVersion < 26 {
		return OutputData{"", nil, nil, nil}
	}

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
		directConns:    make(map[string]*sipb.DirectConn),
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
		// Parse direct connection information.
		if m, _ := historianutils.SubexpNames(directConnRE, l); m {
			p.parsingErrs, p.sensorErrs = p.extractDirectConnInfo()
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

// constructSensorName takes in the name, type, and number of a sensor and
// reconstruct a sensor name if necessary. This function is called only when
// we see multiple sensors sharing the same name.
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

// updateSensorsInfo is a helper function that takes in a map containing sensor
// information stored in bugreportutils.SensorInfo and output a new map storing
// sensor information in *sipb.Sensor.
func (p parser) updateSensorsInfo(sensors map[int32]bugreportutils.SensorInfo) map[int32]*sipb.Sensor {
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
	return p.sensors
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

// To sort the direct connection information, the following interface is used.
type directConns []*sipb.DirectConn

func (slice directConns) Len() int {
	return len(slice)
}

func (slice directConns) Less(i, j int) bool {
	return slice[i].Number < slice[j].Number
}

func (slice directConns) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// allSensorInfo is a function to create the output data after parsing the
// sensorservice dump section. The output contains information for all active
// connections, all sensors' activities grouped by sensors, and all sensors'
// activities grouped by applications.
// TODO: organized the sensors' activities data by applications.s
func (p parser) allSensorInfo() *sipb.AllSensorsInfo {
	allActiveConns := make(activeConns, 0, len(p.activeConns))
	for _, conn := range p.activeConns {
		allActiveConns = append(allActiveConns, conn)
	}
	sort.Sort(allActiveConns)

	allDirectConns := make(directConns, 0, len(p.directConns))
	for _, conn := range p.directConns {
		allDirectConns = append(allDirectConns, conn)
	}
	sort.Sort(allDirectConns)

	allSensors := make(sensors, 0, len(p.sensors))
	for _, sensorInfo := range p.sensors {
		allSensors = append(allSensors, sensorInfo)
	}
	sort.Sort(allSensors)

	return &sipb.AllSensorsInfo{
		AllActiveConns: allActiveConns,
		AllDirectConns: allDirectConns,
		Sensors:        allSensors,
		Apps:           nil,
	}
}

// extractActiveSensorInfo extracts information for active sensors found in
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

// organizeSensorInfoForActiveConn is a helper function that specifically
// handle the sensors' information parsed for each active connection.
// A special case it handles is when there are multiple sensors being activated
// by one active connection, then multiple active connection objects will be
// created.
func (p parser) organizeSensorInfoForActiveConn(connNum int32,
	result map[string]string, connections map[int32]*sipb.ActiveConn) (int32,
	map[int32]*sipb.ActiveConn, []error, []error) {
	n, err := strconv.ParseInt(result["sensorNumber"], 0, 32)
	if err != nil {
		p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
			"%s: connection(%d): error parsing sensorNumber %v:%v",
			parseConnErrStr, connNum, result["sensorNumber"], err))
		return connNum, nil, p.parsingErrs, p.sensorErrs
	}
	sensorNumber := int32(n)
	pendingFlush, err := strconv.Atoi(result["pendingFlush"])
	if err != nil {
		p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
			"%s: connection(%d): error parsing pendingFlush %v:%v",
			parseConnErrStr, connNum, result["pendingFlush"], err))
		return connNum, nil, p.parsingErrs, p.sensorErrs
	}

	if connections[connNum].SensorNumber != -1 {
		newConnNum := connNum + 1
		newConn := &sipb.ActiveConn{
			Number:                 newConnNum,
			OperatingMode:          connections[connNum].OperatingMode,
			PackageName:            connections[connNum].PackageName,
			UID:                    connections[connNum].UID,
			SensorNumber:           -1,
			PendingFlush:           -1,
			SamplingRateHz:         -1,
			BatchingPeriodS:        -1,
			HasSensorserviceRecord: false,
			Source:                 sensorDump,
		}
		connections[newConnNum] = newConn
		connNum = newConnNum
	}
	connections[connNum].SensorNumber = sensorNumber
	connections[connNum].PendingFlush = int32(pendingFlush)
	if activeSensor, exist := p.activeSensors[sensorNumber]; exist {
		connections[connNum].SamplingRateHz = activeSensor.samplingRateHz
		connections[connNum].BatchingPeriodS = activeSensor.batchingPeriodS
	} else {
		p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
			"[Active Connection]: connection(%d): the sensor(%d)"+
				" is not active according to the sensor device section",
			connNum, sensorNumber))
	}
	return connNum, connections, p.parsingErrs, p.sensorErrs
}

// extractActiveConnInfo extracts active connections information found in
// the sensorservice dump of a bugreport.
func (p parser) extractActiveConnInfo() ([]error, []error) {
	curConnNum := int32(0)
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
		if l1, _ := historianutils.SubexpNames(actConnLine1RE, line); l1 {
			// Since proto buff restricts that field numbers must be positive
			// integers, we will not use zero-indexing by adding 1 to
			// all connection number.
			curConnNum++
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
		} else if l2, result := historianutils.SubexpNames(actConnLine2RE, line); l2 {
			connections[curConnNum].OperatingMode = result["connMode"]
		} else if l3, result := historianutils.SubexpNames(actConnLine3RE, line); l3 {
			uid, err := strconv.Atoi(result["uid"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
					"%s: connection(%d): error parsing uid %v:%v",
					parseConnErrStr, curConnNum, result["uid"], err))
				continue
			}
			connections[curConnNum].UID = int32(uid)
			connections[curConnNum].PackageName = result["packageName"]
		} else if l4, result := historianutils.SubexpNames(actConnLine4RE, line); l4 {
			curConnNum, connections, p.parsingErrs, p.sensorErrs =
				p.organizeSensorInfoForActiveConn(curConnNum, result, connections)
		}
	}

	// Build the new map that uses identifier to look up relevant active
	// connection information.
	for _, conn := range connections {
		identifier := fmt.Sprintf("%d,%d,%s", conn.SensorNumber, conn.UID,
			conn.PackageName)
		p.activeConns[identifier] = conn
	}
	return p.parsingErrs, p.sensorErrs
}

// organizeSensorInfoForDirectConn is a helper function that specifically
// handle the sensors' information parsed for each direct connection.
// A special case it handles is when there are multiple sensors being activated
// by one direct connection, then multiple direct connection objects will be
// created.
func (p parser) organizeSensorInfoForDirectConn(connNum int32,
	result map[string]string, connections map[int32]*sipb.DirectConn) (int32,
	map[int32]*sipb.DirectConn, []error, []error) {
	n, err := strconv.ParseInt(result["sensorNumber"], 0, 32)
	if err != nil {
		p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
			"%s: direct connection(%d): error parsing sensorNumber %v:%v",
			parseConnErrStr, connNum, result["sensorNumber"], err))
		return connNum, nil, p.parsingErrs, p.sensorErrs
	}
	sensorNumber := int32(n)
	rateLevel, err := strconv.Atoi(result["rateLevel"])
	if err != nil {
		p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
			"%s: connection(%d): error parsing rate level %v:%v",
			parseConnErrStr, connNum, result["rateLevel"], err))
		return connNum, nil, p.parsingErrs, p.sensorErrs
	}

	if connections[connNum].SensorNumber != -1 {
		newConnNum := connNum + 1
		newConn := &sipb.DirectConn{
			Number:                 newConnNum,
			PackageName:            connections[connNum].PackageName,
			HALChannelHandle:       connections[connNum].HALChannelHandle,
			HasSensorserviceRecord: false,
			Source:                 sensorDump,
		}
		connections[newConnNum] = newConn
		connNum = newConnNum
	}
	connections[connNum].SensorNumber = sensorNumber
	connections[connNum].RateLevel = int32(rateLevel)
	return connNum, connections, p.parsingErrs, p.sensorErrs
}

// extractDirectConnInfo extracts direct connections information found in
// the sensorservice dump of a bugreport.
func (p parser) extractDirectConnInfo() ([]error, []error) {
	curConnNum := int32(0)
	// connections is a map from direct connection number to information
	// for the relevant connection.
	connections := make(map[int32]*sipb.DirectConn)

	for p.valid() {
		line := p.line()
		// The section stops when reaching the previous registration section.
		if m, _ := historianutils.SubexpNames(prevRegistrationRE, line); m {
			p.prevline()
			break
		}

		if m, _ := historianutils.SubexpNames(dirConnLine1RE, line); m {
			curConnNum++
			if _, ok := connections[curConnNum]; !ok {
				connections[curConnNum] = &sipb.DirectConn{
					Number:                 curConnNum,
					PackageName:            ``,
					HALChannelHandle:       -1,
					SensorNumber:           -1,
					HasSensorserviceRecord: false,
					Source:                 sensorDump,
				}
			}
		} else if m, result := historianutils.SubexpNames(dirConnLine2RE, line); m {
			connections[curConnNum].PackageName = result["packageName"]
			halHandle, err := strconv.Atoi(result["halHandle"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
					"%s: connection(%d): error parsing uid %v:%v",
					parseConnErrStr, curConnNum, result["uid"], err))
				continue
			}
			connections[curConnNum].HALChannelHandle = int32(halHandle)
		} else if m, result := historianutils.SubexpNames(dirConnLine3RE, line); m {
			curConnNum, connections, p.parsingErrs, p.sensorErrs =
				p.organizeSensorInfoForDirectConn(curConnNum, result, connections)
		}
	}

	// Build the new map that uses identifier to look up relevant active
	// connection information.
	for _, conn := range connections {
		identifier := fmt.Sprintf("%d,%s", conn.SensorNumber, conn.PackageName)
		p.directConns[identifier] = conn
	}
	return p.parsingErrs, p.sensorErrs
}

// createTimestampMs is a helper function that parses the time information for
// one line and generates the timestamp in ms. It also accomodate the case
// where the time information includes date.
func (p *parser) createTimestampMs(line string, result map[string]string) (int64, []error) {
	hasDate, date := historianutils.SubexpNames(timeLayoutRE, line)
	var timestampMs int64
	var timestampErr error
	if hasDate {
		month, err := strconv.Atoi(date["month"])
		if err != nil {
			p.parsingErrs = append(p.parsingErrs,
				fmt.Errorf("%s: error parsing month value for line %v: %v",
					parseRegErrStr, line, timestampErr))
			return -1, p.parsingErrs
		}
		day, err := strconv.Atoi(date["day"])
		if err != nil {
			p.parsingErrs = append(p.parsingErrs,
				fmt.Errorf("%s: error parsing day value for line %v: %v",
					parseRegErrStr, line, timestampErr))
			return -1, p.parsingErrs
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
				parseRegErrStr, line, timestampErr))
		return -1, p.parsingErrs
	}
	if p.earliestTimestampMs > timestampMs {
		p.earliestTimestampMs = timestampMs
	}
	return timestampMs, p.parsingErrs
}

// checkSamplingBatchingData is a helper function that checks whether the
// sampling rate and batching period values obtained from the history section
// match the values obtained from the active connection section.
// [Active Sensor] errors will be reported if there is a mis-match.
func (p *parser) checkSamplingBatchingData(packageName string,
	sensorNumber, uid int32, samplingRateHz, batchingPeriodS float64) []error {
	identifier := fmt.Sprintf("%d,%d,%s", sensorNumber, uid, packageName)
	conn := p.activeConns[identifier]
	if samplingRateHz != conn.SamplingRateHz {
		p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
			"[Active Sensor]: active connection for pkg(%s) and sensor(%d) "+
				"shows two sampling rate(Hz): %.2f at active sensor section; "+
				"%.2f at history section", packageName, sensorNumber,
			conn.SamplingRateHz, samplingRateHz))
		if conn.SamplingRateHz == -1 {
			p.activeConns[identifier].SamplingRateHz = samplingRateHz
		}
	}
	if batchingPeriodS != conn.BatchingPeriodS {
		p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
			"[Active Sensor]: active connection for pkg(%s) and sensor(%d) "+
				"shows two batching period(s): %.2f at active sensor section; "+
				"%.2f at history section", packageName, sensorNumber,
			conn.BatchingPeriodS, batchingPeriodS))
		if conn.BatchingPeriodS == -1 {
			p.activeConns[identifier].BatchingPeriodS = batchingPeriodS
		}
	}
	return p.sensorErrs
}

// processActivation is a helper function that process the activation
// statement in the sensorservice dump.
func (p *parser) processActivation(timestampMs int64, sensorNumber, uid int32,
	packageName, l string) ([]error, []error) {
	_, result := historianutils.SubexpNames(addRegistrationRE, l)
	referenceTimestampMs, _ := p.fullTimestampInMs(p.referenceMonth,
		p.referenceDay, p.referenceTime)
	identifier := fmt.Sprintf("%d,%d,%s", sensorNumber, uid, packageName)
	sensorName := p.sensors[sensorNumber].Name

	samplingPeriodUs, err := strconv.Atoi(result["samplingPeriodUs"])
	if err != nil {
		p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
			"%s: error parsing samplingPeriod %v us for line %v: %v",
			parseRegErrStr, result["samplingPeriodUs"], l, err))
		return p.parsingErrs, p.sensorErrs
	}
	batchingPeriodUs, err := strconv.Atoi(result["batchingPeriodUs"])
	if err != nil {
		p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
			"%s: error parsing batchingPeriod %v us for line %v: %v",
			parseRegErrStr, result["batchingPeriodUs"], l, err))
		return p.parsingErrs, p.sensorErrs
	}
	samplingRateHz := historianutils.PeriodUsToRateHz(samplingPeriodUs)
	batchingPeriodS := math.Round(float64(batchingPeriodUs)*1e-04) / 100

	start := msToTime(timestampMs).In(p.loc).Format(timeFormat)
	if _, exist := p.history[identifier]; !exist {
		// If there is no history of de-activating a subscription,
		// the subscription has to be active.
		if conn, isActive := p.activeConns[identifier]; isActive {
			p.checkSamplingBatchingData(packageName, sensorNumber, int32(uid),
				samplingRateHz, batchingPeriodS)
			// For active connection, set current time as the end time
			// for the ongoing subscription event.
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
					"and sensor(%d) should be active",
				packageName, sensorNumber))
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
			end := msToTime(eventInfo.EndMs).In(p.loc).Format(timeFormat)
			value := fmt.Sprintf("%v,%v,%d,%s,%d,%s,%.2f,%.2f,%s", start,
				end, sensorNumber, p.sensors[sensorNumber].RequestMode,
				uid, packageName, samplingRateHz, batchingPeriodS, sensorDump)
			p.csvState.Print(sensorName, "string", timestampMs, eventInfo.EndMs,
				value, "")
		}
	}
	return p.parsingErrs, p.sensorErrs
}

// processDeActivation is a helper function that processes the deactivation
// statement in the sensorservice dump.
func (p *parser) processDeActivation(timestampMs int64, sensorNumber, uid int32,
	packageName string) []error {
	identifier := fmt.Sprintf("%d,%d,%s", sensorNumber, uid, packageName)
	if event, exist := p.history[identifier]; exist {
		// The current subscription combo has been seen.
		if event.StartMs == -1 {
			p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
				"[Multiple De-Activation]: for pkg(%s) and sensor(%d)",
				packageName, sensorNumber))
		} else {
			// Current de-activation statement will be counted as a new event.
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
	return p.sensorErrs
}

// extractRegistrationHistory extracts all previous registration information
// found in the sensorservice dump of a bug report.
// Note that the previous registration history records the subscription event
// in reverse chronological order.
func (p *parser) extractRegistrationHistory() ([]error, []error) {
	for p.valid() {
		l := p.line()
		var result map[string]string
		isAdd := false
		if m, match := historianutils.SubexpNames(addRegistrationRE, l); m {
			isAdd = true
			result = match
		} else if m, match := historianutils.SubexpNames(removeRegistrationRE, l); m {
			result = match
		} else {
			// Reach the end of the registration section.
			break
		}

		// Get the timestamp of the record.
		var timestampMs int64
		timestampMs, p.parsingErrs = p.createTimestampMs(l, result)
		if timestampMs == -1 {
			continue
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

		if isAdd {
			p.parsingErrs, p.sensorErrs = p.processActivation(timestampMs,
				sensorNumber, int32(uid), packageName, l)
		} else {
			p.sensorErrs = p.processDeActivation(timestampMs, sensorNumber,
				int32(uid), packageName)
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
