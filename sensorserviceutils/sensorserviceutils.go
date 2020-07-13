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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/googleinterns/sensor-historian/bugreportutils"
	"github.com/googleinterns/sensor-historian/csv"
	"github.com/googleinterns/sensor-historian/historianutils"
	acpb "github.com/googleinterns/sensor-historian/pb/activeconnection_proto"
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
		`.*` + `selected = (?P<samplingPeriodms>[0-9]*\.?[0-9]+) ms;` + `.*` +
		`selected = (?P<batchingPeriodms>[0-9]*\.?[0-9]+) ms`)

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
	addRegistrationRE = regexp.MustCompile(`(?P<timeStamp>\d+\:\d+\:\d+)\s*` +
		`\+` + `\s*(?P<sensorNumber>0x?[0-9A-Fa-f]+)` + `\s*pid=\s*` +
		`(?P<pid>\d+)` + `\s*uid=\s*` + `(?P<uid>\d+)` + `\s*package=\s*` +
		`(?P<packageName>[^(]+)` + `\s*samplingPeriod=\s*` +
		`(?P<samplingPeriodus>\d+)us` + `\s*batchingPeriod=\s*` +
		`(?P<batchingPeriodus>\d+)us`)

	// removeRegistrationRE is a regular expression to match the log that
	// removes subscription in the sensorservice dump in the bugreport
	// for Android starting from NRD42 and onwards.
	removeRegistrationRE = regexp.MustCompile(`(?P<timeStamp>\d+\:\d+\:\d+)` +
		`\s*` + `\-` + `\s*(?P<sensorNumber>0x?[0-9A-Fa-f]+)` + `\s*pid=\s*` +
		`(?P<pid>\d+)` + `\s*uid=\s*` + `(?P<uid>\d+)` + `\s*package=\s*` +
		`(?P<packageName>[^(]+)`)

	// timeLayoutRE is a regular expression to match the timestamp with dates
	// that may show up in the bugreport.
	timeLayoutRE = regexp.MustCompile(`^(?P<month>\d+)\-(?P<day>\d+)`)
)

const (
	timeFormat      = "15:04:05"
	sensorRegisDesc = "Sensorservice Registration"
	activeConnDesc  = "Active Connection"
	completeStr     = "complete"
	activeStr       = "active"
	errorStr        = "error"
	parseConnErrStr = "Parse Active Conn"
	parseRegErrStr  = "Parse Registration"
	sensorErrStr    = "Subscription Error"
	// unknownTime is used when the start or end time of an event is unknown.
	// This is not zero as csv.AddEntryWithOpt ignores events with a zero time.
	unknownTime = -1
)

// OutputData contains information for active connection and previous
// registration history collected in the sensorservice dump.
type OutputData struct {
	CSV         string
	ActiveConns map[int32]*acpb.ActiveConn
	ParsingErrs []error
	SensorErrs  []error
}

// activeSensor contains information about an active sensor. All relevant
// information comes from the active sensor section in the sensorservice dump.
type activeSensor struct {
	sensorNumber     int32
	samplingPeriodus int32
	batchingPeriodus int32
}

// SubscriptionInfo contains information about one subscription event of
// a sensor to an application.
// For NRD42 and onwards Android versions: each subscription event is captured
// by the + statement that adds the subscription and the - statement that
// removes the subscription .
// For MNC or before: each subscription event is captured by
// activated/de-activated statments.
type SubscriptionInfo struct {
	StartMs, EndMs   int64
	SensorNumber     int32
	UID              int32
	PackageName      string
	SamplingPeriodus int32
	BatchingPeriodus int32
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
	referenceTime string

	// earliestTimeSeen is the timestamp corresponding to the last event
	// recorded in the Previous Registration section. If there is no previous
	// registration section, ealiestTimeSeen is set to be the timestamp for
	// referenceTime.
	earliestTimeSeen int64

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
	sensors map[int32]bugreportutils.SensorInfo

	// activeSensors is a map from sensor number to the relevant sensor's
	// information. This map only contains information for active sensors.
	activeSensors map[int32]activeSensor

	// activeConns is a map from an identifier to the relevant connection
	// information.
	// If a sensor is actively subscribed by a package when the bugreport is
	// generated, the relevant connection information can be obtained using
	// an identifier formed by concatenating sensor number and package name.
	activeConns map[string]*acpb.ActiveConn

	// history is a map from an identifier to an sensor subscription event.
	// Note that the identifier is a string formed by concatenating
	// sensor number and name of the package that subscribes the sensor.
	history map[string]*SubscriptionInfo
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
		activeConns:    make(map[string]*acpb.ActiveConn),
		history:        make(map[string]*SubscriptionInfo),
		sensors:        meta.Sensors,
	}
	referenceTimestamp, _ := p.fullTimestamp(p.referenceMonth,
		p.referenceDay, p.referenceTime)
	p.earliestTimeSeen = referenceTimestamp

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

	return OutputData{p.buf.String(), p.createActiveConnPBList(),
		p.parsingErrs, p.sensorErrs}
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
			sPeriodms, err := strconv.ParseFloat(result["samplingPeriodms"], 64)
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("[Active Sensor] sensor(%v): error parsing "+
						"sampling period %v for line %v:%v", sensorNumber,
						result["samplingPeriodms"], line, err))
				continue
			}
			bPeriodms, err := strconv.ParseFloat(result["batchingPeriodms"], 64)
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("[Active Sensor] sensor(%v): error parsing "+
						"batching period %v for line %v:%v", sensorNumber,
						result["batchingPeriodms"], line, err))
				continue
			}
			p.activeSensors[sensorNumber] = activeSensor{
				sensorNumber:     sensorNumber,
				samplingPeriodus: int32(sPeriodms * 1000),
				batchingPeriodus: int32(bPeriodms * 1000),
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
	connections := make(map[int32]*acpb.ActiveConn)

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
				connections[curConnNum] = &acpb.ActiveConn{
					Number:           curConnNum,
					OperatingMode:    ``,
					PackageName:      ``,
					UID:              -1,
					SensorNumber:     -1,
					PendingFlush:     -1,
					SamplingPeriodus: -1,
					BatchingPeriodus: -1,
					HasRecord:        false,
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
					connections[curConnNum].SamplingPeriodus = activeSensor.samplingPeriodus
					connections[curConnNum].BatchingPeriodus = activeSensor.batchingPeriodus
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

// createActiveConnPBList creates a list of active connection information
// based on the map built while parsing sensorservice dump.
func (p *parser) createActiveConnPBList() map[int32]*acpb.ActiveConn {
	activeConnections := make(map[int32]*acpb.ActiveConn)
	for _, conn := range p.activeConns {
		activeConnections[conn.Number] = conn
	}
	return activeConnections
}

// extractRegistrationHistory extracts all previous registration information
// found in the sensorservice dump of a bug report.
func (p *parser) extractRegistrationHistory() ([]error, []error) {
	referenceTimestamp, _ := p.fullTimestamp(p.referenceMonth,
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

		// Get the timestamp of the record.
		// Accomodate the case where the timestamp includes date.
		hasDate, date := historianutils.SubexpNames(timeLayoutRE, l)
		var timestamp int64
		var timestampErr error
		if hasDate {
			month, err := strconv.Atoi(date["month"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("%s: error parsing timestamp for line %v: %v",
						parseRegErrStr, l, timestampErr))
				continue
			}
			day, err := strconv.Atoi(date["day"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("%s: error parsing timestamp for line %v: %v",
						parseRegErrStr, l, timestampErr))
				continue
			}
			timestamp, timestampErr = p.fullTimestamp(month, day,
				result["timeStamp"])
		} else {
			timestamp, timestampErr = p.fullTimestamp(p.referenceMonth,
				p.referenceDay, result["timeStamp"])
		}
		if timestampErr != nil {
			p.parsingErrs = append(p.parsingErrs,
				fmt.Errorf("%s: error parsing timestamp for line %v: %v",
					parseRegErrStr, l, timestampErr))
			continue
		}
		if p.earliestTimeSeen > timestamp {
			p.earliestTimeSeen = timestamp
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
				"%s: sensor %d: invalid subscription for an "+
					"non-existing sensor", sensorErrStr, sensorNumber))
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

		var value string
		if isAdd {
			// Currently processing an activated statement.
			samplingPeriodus, err := strconv.Atoi(result["samplingPeriodus"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
					"%s: error parsing samplingPeriod %v us for line %v: %v",
					parseRegErrStr, result["samplingPeriodus"], l, err))
				continue
			}
			batchingPeriodus, err := strconv.Atoi(result["batchingPeriodus"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs, fmt.Errorf(
					"%s: error parsing batchingPeriod %v us for line %v: %v",
					parseRegErrStr, result["batchingPeriodus"], l, err))
				continue
			}
			value = fmt.Sprintf("%d,%d,%s,%d,%d", sensorNumber,
				uid, packageName, samplingPeriodus, batchingPeriodus)

			_, exist := p.history[identifier]
			if !exist {
				// If there is no history of de-activating a subscription,
				// the subscription has to be active.
				if conn, isActiveConn := p.activeConns[identifier]; isActiveConn {
					// For active connection, set current time as the end time
					// for the ongoing subscription event.
					p.csvState.Print(sensorRegisDesc, "string", timestamp,
						referenceTimestamp, value, "")
					conn.HasRecord = true
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
					eventInfo.StartMs = timestamp
					eventInfo.SamplingPeriodus = int32(samplingPeriodus)
					eventInfo.BatchingPeriodus = int32(batchingPeriodus)
					p.csvState.Print(sensorRegisDesc, "string",
						timestamp, eventInfo.EndMs, value, "")
				}
			}
		} else {
			// Currently processing an de-activation statement.
			if event, exist := p.history[identifier]; exist {
				if event.StartMs == -1 {
					p.sensorErrs = append(p.sensorErrs, fmt.Errorf(
						"[Multiple De-Activation]: for pkg(%s) and sensor(%d)",
						packageName, sensorNumber))
				} else {
					// Current de-activation statement will be counted as
					// a new subscription event.
					eventInfo := &SubscriptionInfo{
						StartMs:      -1,
						EndMs:        timestamp,
						SensorNumber: sensorNumber,
						PackageName:  packageName,
					}
					p.history[identifier] = eventInfo
				}
			} else {
				eventInfo := &SubscriptionInfo{
					StartMs:      -1,
					EndMs:        timestamp,
					SensorNumber: sensorNumber,
					PackageName:  packageName,
				}
				p.history[identifier] = eventInfo
			}
		}
	}

	return p.parsingErrs, p.sensorErrs
}

// To sort the active connection information, the following interface is used.s
type activeConns []*acpb.ActiveConn

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
	referenceTimestamp, _ := p.fullTimestamp(p.referenceMonth,
		p.referenceDay, p.referenceTime)

	// Store all the active connections without history in a list and order
	// the list by the connection number.
	connNoHistory := make(activeConns, 0, len(p.activeConns))
	for _, conn := range p.activeConns {
		if !conn.HasRecord {
			connNoHistory = append(connNoHistory, conn)
		}
	}
	sort.Sort(connNoHistory)

	for _, conn := range connNoHistory {
		value := fmt.Sprintf("%d,%d,%s,%d,%d", conn.SensorNumber, conn.UID,
			conn.PackageName, conn.SamplingPeriodus, conn.BatchingPeriodus)
		p.csvState.Print(sensorRegisDesc, "string", p.earliestTimeSeen,
			referenceTimestamp, value, "")
	}
}

// This function is directly copied from the activity.go file.
func validMonth(m int) bool {
	return m >= int(time.January) && m <= int(time.December)
}

// This function is directly copied from the activity.go file.
// fullTimestamp constructs the unix ms timestamp from the given date and
// time information.
// Since previous registration events have no corresponding year,
// we reconstruct the full timestamp using the stored reference year and
// month extracted from the dumpstate line of the bug report.
func (p *parser) fullTimestamp(month, day int, partialTimestamp string) (int64, error) {
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

// This function is directly copied froms the activity.go file.
// msToTime converts milliseconds since Unix Epoch to a time.Time object.
func msToTime(ms int64) time.Time {
	return time.Unix(0, ms*int64(time.Millisecond))
}
