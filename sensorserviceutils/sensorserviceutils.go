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

// Package sensorserviceutils is a library of common sensorservice dump parsing functions.
package sensorserviceutils

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/googleinterns/sensor-historian/bugreportutils"
	"github.com/googleinterns/sensor-historian/csv"
	"github.com/googleinterns/sensor-historian/historianutils"
	acpb "github.com/googleinterns/sensor-historian/pb/activeconnection_proto"
	usagepb "github.com/googleinterns/sensor-historian/pb/usagestats_proto"
)

var (
	// Each of the connLineXRE is a regular expression to match the X line of
	// connection information in the sensorservice dump in the bugreport across all version.
	connLineOneRE   = regexp.MustCompile(`\s*Connection\s+Number:\s*` + `(?P<connNum>\d+)`)
	connLineTwoRE   = regexp.MustCompile(`\s*Operating\s+Mode: (?P<connMode>[^(]+)` + `\s*`)
	connLineThreeRE = regexp.MustCompile(`\s*(?P<packageName>[^(]+)` + `\s*\|\s*` +
		`WakeLockRefCount\s*(?P<wakeLockRefCount>\d+)` + `\s*\|\s*` + `uid\s*(?P<uid>\d+)`)
	connLineFourRE = regexp.MustCompile(`(?P<sensorNumber>0x?[0-9A-Fa-f]+)` + `\s*\|\s*` +
		`status:\s*(?P<status>[^(]+)` + `\s*\|\s*` + `pending\s*flush\s*events\s*` +
		`(?P<pendingFlush>\d+)`)

	// activeConnRE is a regular expression to match the section for active connections in the
	// sensorservice dump in the bugreport across all version.
	activeConnRE = regexp.MustCompile(`\s*active\s*connections\s*`)

	// directConnRE is a regular expression to match the section for direct connections in the
	// sensorservice dump in the bugreport across all version.
	directConnRE = regexp.MustCompile(`\s*direct\s*connections\s*`)

	// prevRegistrationRE is a regular expression to match the section for previous connections i
	// in the sensorservice dump in the bugreport across all version.
	prevRegistrationRE = regexp.MustCompile(`Previous` + `\s*` + `Registrations:`)

	// addRegistrationRE is a regular expression to match the log that adds subscription in the
	// sensorservice dump in the bugreport starting from NRD42 and onwards.
	addRegistrationRE = regexp.MustCompile(`(?P<timeStamp>\d+\:\d+\:\d+)` + `\s*` + `\+` +
		`\s*(?P<sensorNumber>0x?[0-9A-Fa-f]+)` + `\s*pid=\s*` + `(?P<pid>\d+)` +
		`\s*uid=\s*` + `(?P<uid>\d+)` + `\s*package=\s*` + `(?P<packageName>[^(]+)` +
		`\s*samplingPeriod=\s*` + `(?P<samplingPeriod>\d+)us` + `\s*batchingPeriod=\s*` +
		`(?P<batchingPeriod>\d+)us`)

	// removeRegistrationRE is a regular expression to match the log that removes subscription in
	// the sensorservice dump in the bugreport starting from NRD42 and onwards.
	removeRegistrationRE = regexp.MustCompile(`(?P<timeStamp>\d+\:\d+\:\d+)` + `\s*` + `\-` +
		`\s*(?P<sensorNumber>0x?[0-9A-Fa-f]+)` + `\s*pid=\s*` + `(?P<pid>\d+)` +
		`\s*uid=\s*` + `(?P<uid>\d+)` + `\s*package=\s*` + `(?P<packageName>[^(]+)`)

	// timeLayoutRE is a regular expression to match the timestamp with dates that may probably
	// show up in the bugreport.
	timeLayoutRE = regexp.MustCompile(`^(?P<month>\d+)-(?P<day>\d+)`)
)

const (
	sensorRegisDesc = "Sensorservice Registration"
	activeConnDesc  = "Active Connection"
	completeStr     = "complete"
	activeStr       = "active"
	errorStr        = "error"
	// unknownTime is used when the start or end time of an event is unknown.
	// This is not zero as csv.AddEntryWithOpt ignores events with a zero time.
	unknownTime = -1
)

// OutputData contains information for active connection and previous registration history collected
// in the sensorservice dump.
type OutputData struct {
	CSV         string
	ActiveConns []*acpb.ActiveConn
	ParsingErrs []error
	SensorErrs  []error
}

// SubscriptionInfo contains information about one subscription event of a sensor to an application.
// For NRD42 and onwards Android versions: each subscription event is captured by the + statement
// that adds the subscription and the - statement that removes the subscription .
// For MNC or before: each subscription event is captured by the activated/de-activated statments.
type SubscriptionInfo struct {
	StartMs, EndMs int64
	SensorNumber   int32
	PackageName    string
	SamplingPeriod int32
	BatchingPeroid int32
}

type parser struct {
	// referenceYear is the year extracted from the dumpstate line in a bugreport.
	// Previous Registration lines don't contain a year in the date string, so we use this
	// to reconstruct the full timestamp.
	referenceYear int

	// referenceMonth is the month extracted from the dumpstate line in a bugreport.
	// Since a bugreport may span over a year boundary, we use the month to check whether the
	// year for the event needs to be decremented or incremented.
	referenceMonth time.Month

	// referenceDay is the month extracted from the dumpstate line in a bugreport.
	referenceDay int

	// loc is the location parsed from timezone information in the bugreport.
	// The previous registration is in the user's local timezone which we need to convert to UTC time.
	loc *time.Location

	lines []string
	idx   int

	buf         *bytes.Buffer
	csvState    *csv.State
	parsingErrs []error
	sensorErrs  []error

	// sensors is a map from sensor number to the relevant sensor's information.
	sensors map[int32]bugreportutils.SensorInfo

	// activeConns is a map from an identifier to the relevant connection information.
	// If a sensor is actively subscribed by a package when the bugreport is generated, the relevant
	// connection information can be obtained using the identifier formed by concatenating
	// sensor number and name of the package.
	activeConns map[string]*acpb.ActiveConn

	// history is a map from an identifier to an sensor subscription event.
	// Note that the identifier is a string formed by concatenating sensor number and name of
	// the package that subscribes the sensor.
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

// Parse function collects information regarding active connections and records availalbe sensor
// subscription events in the sensorservice section as CSV entry.
// Errors encountered during parsing will be collected into an errors slice and
// will continue parsing remaining events.
func Parse(f string, meta *bugreportutils.MetaInfo) OutputData {
	loc, err := bugreportutils.TimeZone(f)
	if err != nil {
		return OutputData{"", nil, nil, []error{err}}
	}
	// Extract the year and month from the bugreport dumpstate line.
	d, err := bugreportutils.DumpState(f)
	if err != nil {
		return OutputData{"", nil, nil,
			[]error{fmt.Errorf("could not find dumpstate information in the bugreport: %v", err)}}
	}
	buf := new(bytes.Buffer)
	p := &parser{
		referenceYear:  d.Year(),
		referenceMonth: d.Month(),
		referenceDay:   d.Day(),
		loc:            loc,
		buf:            buf,
		csvState:       csv.NewState(buf, true),
		lines:          strings.Split(f, "\n"),
		activeConns:    make(map[string]*acpb.ActiveConn),
		history:        make(map[string]*SubscriptionInfo),
		sensors:        meta.Sensors,
	}

	for p.valid() {
		l := p.line() // Read the current line and advance the line position.
		// Active connection parsing.
		if m, _ := historianutils.SubexpNames(activeConnRE, l); m {
			if err := p.extractActiveConnInfo(); err != nil {
				p.parsingErrs = append(p.parsingErrs, err)
			}
			continue
		}
	}
	return OutputData{"", p.createActiveConnPBList(), p.sensorErrs, p.parsingErrs}
}

// extractActiveConnInfo extracts active connections information found in the sensorservice dump of
// a bugreport.
func (p parser) extractActiveConnInfo() error {
	curConnNum := int32(-1)
	// connections is a map from active connection number to information for the relevant connection.
	connections := make(map[int32]*acpb.ActiveConn)

	for p.valid() {
		line := p.line()
		// Stop when reaching the section about direct connection.
		if inDirectConn, _ := historianutils.SubexpNames(directConnRE, line); inDirectConn {
			p.prevline()
			break
		}
		// In Android MNC or before, the direct connesction section may not exist if there is no
		// direct connection. So the section stops when reaching the previous registration section.
		if inPrevRegis, _ := historianutils.SubexpNames(prevRegistrationRE, line); inPrevRegis {
			p.prevline()
			break
		}
		// For all Android version: each active connection's information needs four lines to record.
		if lineOne, result := historianutils.SubexpNames(connLineOneRE, line); lineOne {
			connNum, err := strconv.Atoi(result["connNum"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("could not parse connection number %v:%v", result["connNum"], err))
				continue
			}
			// Since proto buff restricts that field numbers must be positive integers,
			// we will not use zero-indexing by adding 1 to all the connection number.
			curConnNum = int32(connNum) + 1
			if _, ok := connections[curConnNum]; !ok {
				connections[curConnNum] = &acpb.ActiveConn{
					Number:        curConnNum,
					UID:           -1,
					PendingFlush:  -1,
					SensorNumber:  -1,
					OperatingMode: ``,
					PackageName:   ``,
				}
			}
		} else {
			_, ok := connections[curConnNum]
			if !ok {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("no information regarding connection %v", curConnNum))
				continue
			}
			if lineTwo, result := historianutils.SubexpNames(connLineTwoRE, line); lineTwo {
				connections[curConnNum].OperatingMode = result["connMode"]
			} else if lineThree, result := historianutils.SubexpNames(connLineThreeRE, line); lineThree {
				uid, err := strconv.Atoi(result["uid"])
				if err != nil {
					p.parsingErrs = append(p.parsingErrs,
						fmt.Errorf("active connection %d: cannot parse uid %v:%v",
							curConnNum, result["uid"], err))
					continue
				}
				connections[curConnNum].UID = int32(uid)
				connections[curConnNum].PackageName = result["packageName"]
			} else if lineFour, result := historianutils.SubexpNames(connLineFourRE, line); lineFour {
				sensorNumber, err := strconv.ParseInt(result["sensorNumber"], 0, 32)
				if err != nil {
					p.parsingErrs = append(p.parsingErrs,
						fmt.Errorf("active connection %d: cannot parse sensor handle %v:%v",
							curConnNum, result["sensorNumber"], err))
					continue
				}
				sensor := int32(sensorNumber)
				connections[curConnNum].SensorNumber = sensor
				pendingFlush, err := strconv.Atoi(result["pendingFlush"])
				if err != nil {
					p.parsingErrs = append(p.parsingErrs,
						fmt.Errorf("active connection %d: cannot parse pendingFlush %v:%v",
							curConnNum, result["uid"], err))
					continue
				}
				connections[curConnNum].PendingFlush = int32(pendingFlush)
			}
		}
	}

	// Build the new map that uses identifier to look up relevant active connection information.
	for _, conn := range connections {
		identifier := fmt.Sprintf("%d,%s", conn.SensorNumber, conn.PackageName)
		p.activeConns[identifier] = conn
	}

	return nil
}

// createActiveConnPBList creates a list of active connection information based on the map built while
// parsing sensorservice dump.
func (p *parser) createActiveConnPBList() []*acpb.ActiveConn {
	var activeConnections []*acpb.ActiveConn
	for _, conn := range p.activeConns {
		activeConnections = append(activeConnections, conn)
	}
	return activeConnections
}

// extractRegistrationHistory extracts all previous registration information found
// in the sensorservice dump of a bug report.
func (p *parser) extractRegistrationHistory(pkgInfos []*usagepb.PackageInfo) error {
	for p.valid() {
		l := p.line()
		var result map[string]string
		isAdd := false
		if add, match := historianutils.SubexpNames(addRegistrationRE, l); add {
			result = match
			isAdd = true
		} else if remove, match := historianutils.SubexpNames(removeRegistrationRE, l); remove {
			result = match
		} else {
			// Reach the end of the previous registration section.
			return nil
		}

		// Get the timestamp of the record.
		hasDate, date := historianutils.SubexpNames(timeLayoutRE, l)
		var timestamp int64
		var timestampErr error
		if hasDate {
			timestamp, timestampErr = p.fullTimestamp(date["month"], date["day"], result["timeStamp"])
		} else {
			month := p.referenceMonth.String()
			day := strconv.Itoa(p.referenceDay)
			timestamp, timestampErr = p.fullTimestamp(month, day, result["timeStamp"])
		}
		if timestampErr != nil {
			p.parsingErrs = append(p.parsingErrs, fmt.Errorf("error parsing timestamp for line %v: %v", l, timestampErr))
			continue
		}

		handle, err := strconv.ParseInt(result["sensorNumber"], 0, 32)
		if err != nil {
			p.parsingErrs = append(p.parsingErrs, fmt.Errorf("error parsing sensorNumber %v for line %v: %v",
				result["sensorNumber"], l, err))
			continue
		}
		sensorNumber := int32(handle)
		_, exist := p.sensors[sensorNumber]
		if !exist {
			p.parsingErrs = append(p.parsingErrs, fmt.Errorf("sensor No.%d: invalid subscription for an non-existing sensor",
				sensorNumber))
			continue
		}
		packageName := result["packageName"]
		identifier := fmt.Sprintf("%d,%s", sensorNumber, packageName)

		var value string
		if isAdd {
			// Activated statements have information for sampling and batching peroid.
			samplingPeriod, err := strconv.Atoi(result["samplingPeriod"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs, fmt.Errorf("error parsing samplingPeriod %v for line %v: %v",
					result["samplingPeriod"], l, err))
				continue
			}
			batchingPeriod, err := strconv.Atoi(result["batchingPeriod"])
			if err != nil {
				p.parsingErrs = append(p.parsingErrs, fmt.Errorf("error parsing batchingPeriod %v for line %v: %v",
					result["batchingPeriod"], l, err))
				continue
			}
			value = fmt.Sprintf("%d,%d,%d,%s",
				sensorNumber, samplingPeriod, batchingPeriod, packageName)
			_, exist := p.history[identifier]
			if !exist {
				// If there is no history of removing a subscription, the subscription has to be active.
				if _, isActive := p.activeConns[identifier]; isActive {
					//recordActiveConnection!
					eventInfo := &SubscriptionInfo{
						StartMs:        timestamp,
						SensorNumber:   sensorNumber,
						PackageName:    packageName,
						SamplingPeriod: int32(samplingPeriod),
						BatchingPeroid: int32(batchingPeriod),
					}
					p.history[identifier] = eventInfo
				} else {
					p.parsingErrs = append(p.parsingErrs,
						fmt.Errorf("pkg=%s: this app has a lingering subscription to sensor No.%d",
							packageName, sensorNumber))
				}
			} else {
				//make an event!
				eventInfo := p.history[identifier]
				eventInfo.StartMs = timestamp
				eventInfo.SamplingPeriod = int32(samplingPeriod)
				eventInfo.BatchingPeroid = int32(batchingPeriod)
				entry := csv.Entry{
					Desc:       sensorRegisDesc,
					Start:      eventInfo.StartMs,
					Type:       activeConnDesc,
					Identifier: identifier,
					Value:      value,
				}
				p.csvState.StartEvent(entry)
				p.csvState.EndEvent(sensorRegisDesc, identifier, eventInfo.EndMs)
				delete(p.history, identifier)
			}
		} else {
			// The history vairable only has an event if the package has unsubscribed the sensor.
			if _, exist := p.history[identifier]; exist {
				p.parsingErrs = append(p.parsingErrs,
					fmt.Errorf("pkg=%s: this app unsubscribed sensor No.%d twice without subscribing it",
						packageName, sensorNumber))
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
	return nil
}

// This function is directly copied from the activity.go file
func validMonth(m int) bool {
	return m >= int(time.January) && m <= int(time.December)
}

// This function is directly copied from the activity.go file
// fullTimestamp constructs the unix ms timestamp from the given date and time information.
// Since previous registration events have no corresponding year, we reconstruct the full timestamp
// using the stored reference year ands month extracted from the dumpstate line of the bug report.
func (p *parser) fullTimestamp(month, day, partialTimestamp string) (int64, error) {
	remainder := "000"
	parsedMonth, err := strconv.Atoi(month)
	if err != nil {
		return 0, err
	}
	if !validMonth(parsedMonth) {
		return 0, fmt.Errorf("invalid month: %d", parsedMonth)
	}
	year := p.referenceYear
	// The reference month and year represents the time the bugreport was taken.
	// Since events do not have the year and may be out of order, we guess the
	// year based on the month the event occurred and the reference month.
	//
	// If the event's month was greater than the reference month by a lot, the event
	// is assumed to have taken place in the year preceding the reference year since
	// it doesn't make sense for events to exist so long after the bugreport was taken.
	// e.g. Reference date: March 2016, Event month: October, year assumed to be 2015.
	//
	// If the bug report event log begins near the end of a year, and rolls over to the next year,
	// the event would have taken place in the year preceding the reference year.
	if int(p.referenceMonth)-parsedMonth < -1 {
		year--
		// Some events may still occur after the given reference date,
		// so we check for a year rollover in the other direction.
	} else if p.referenceMonth == time.December && time.Month(parsedMonth) == time.January {
		year++
	}
	return bugreportutils.TimeStampToMs(fmt.Sprintf("%d-%s-%s %s", year, month, day, partialTimestamp),
		remainder, p.loc)
}

// This function is directly copied froms the activity.go file
// msToTime converts milliseconds since Unix Epoch to a time.Time object.
func msToTime(ms int64) time.Time {
	return time.Unix(0, ms*int64(time.Millisecond))
}
