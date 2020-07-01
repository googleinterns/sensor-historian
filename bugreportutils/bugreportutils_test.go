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

package bugreportutils

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Tests the conversion of times in the format: "2015-05-28 19:50:27.636636" to unix time in ms.
// This is parsed into two separate strings "2015-05-28 19:50:27" and "636636".
func TestTimeStampToMs(t *testing.T) {
	tests := []struct {
		desc      string
		timestamp string
		remainder string
		loc       *time.Location
		want      int64
		wantErr   error
	}{
		{
			desc:      "UTC location",
			timestamp: "2015-05-28 19:50:27",
			remainder: "636636",
			loc:       time.UTC,
			want:      1432842627636,
		},
		{
			desc:      "An hour east of UTC",
			timestamp: "2015-05-28 19:50:27",
			remainder: "636636",
			loc:       time.FixedZone("an hour east of UTC", 3600),
			want:      (1432842627636 - 3600000),
		},
		{
			desc:      "Missing location",
			timestamp: "2015-05-28 19:50:27",
			remainder: "636636",
			wantErr:   errors.New("missing location"),
		},
		{
			desc:      "Missing remainder",
			timestamp: "2015-05-28 19:50:27",
			loc:       time.UTC,
			want:      1432842627000,
		},
		{
			desc:      "Length of remainder < 3",
			timestamp: "2015-05-28 19:50:27.6",
			remainder: "6",
			loc:       time.UTC,
			want:      1432842627600,
		},
	}
	for _, test := range tests {
		got, err := TimeStampToMs(test.timestamp, test.remainder, test.loc)
		if !reflect.DeepEqual(err, test.wantErr) {
			t.Errorf("%v: TimeStampToMs(%v, %v)\n got err: %v\n want err: %v", test.desc, test.timestamp, test.remainder, err, test.wantErr)
		}
		if got != test.want {
			t.Errorf("%v: TimeStampToMs(%v, %v)\n got: %v\n want: %v", test.desc, test.timestamp, test.remainder, got, test.want)
		}
	}
}

// Tests the extracting of the time zone from a bug report.
func TestTimeZone(t *testing.T) {
	tests := []struct {
		desc    string
		input   []string
		want    string
		wantErr error
	}{
		{
			desc: "Europe/London time zone",
			input: []string{
				`========================================================`,
				`== dumpstate: 2015-07-07 18:07:00`,
				`========================================================`,
				``,
				`Build: LYZ28H`,
				`...`,
				`[persist.sys.localevar]: []`,
				`[persist.sys.media.use-awesome]: [true]`,
				`[persist.sys.profiler_ms]: [0]`,
				`[persist.sys.timezone]: [Europe/London]`,
			},
			want: "Europe/London",
		},
		{
			desc: "America/Los_Angeles time zone",
			input: []string{
				`========================================================`,
				`== dumpstate: 2015-07-31 09:20:54`,
				`========================================================`,
				``,
				`Build: shamu-userdebug M MRA16G 2097933 dev-keys`,
				`..`,
				`[persist.sys.qc.sub.rdump.on]: [0]`,
				`[persist.sys.timezone]: [America/Los_Angeles]`,
				`[persist.sys.usb.config]: [adb]`,
				`[ril.baseband.config.version]: [SHAMU_TMO_CUST]`,
			},
			want: "America/Los_Angeles",
		},
		{
			desc: "Invalid time zone",
			input: []string{
				`========================================================`,
				`== dumpstate: 2015-07-31 09:20:54`,
				`========================================================`,
				``,
				`Build: shamu-userdebug M MRA16G 2097933 dev-keys`,
				`..`,
				`[persist.sys.qc.sub.rdump.on]: [0]`,
				`[persist.sys.timezone]: [Invalid]`,
				`[persist.sys.usb.config]: [adb]`,
				`[ril.baseband.config.version]: [SHAMU_TMO_CUST]`,
			},
			wantErr: errors.New("unknown time zone Invalid"),
		},
		{
			desc: "Missing time zone",
			input: []string{
				`========================================================`,
				`== dumpstate: 2015-07-31 09:20:54`,
				`========================================================`,
				``,
				`Build: shamu-userdebug M MRA16G 2097933 dev-keys`,
				`..`,
				`[persist.sys.qc.sub.rdump.on]: [0]`,
				`[persist.sys.usb.config]: [adb]`,
				`[ril.baseband.config.version]: [SHAMU_TMO_CUST]`,
			},
			want: "UTC",
		},
	}
	for _, test := range tests {
		input := strings.Join(test.input, "\n")
		got, err := TimeZone(input)

		if !reflect.DeepEqual(err, test.wantErr) {
			t.Errorf("%v: TimeZone(%v)\n got err: %v\n want err: %v", test.desc, input, err, test.wantErr)
		}
		if test.wantErr != nil {
			continue
		}
		if got.String() != test.want {
			t.Errorf("%v: TimeZone(%v)\n got: %q\n want: %q", test.desc, input, got.String(), test.want)
		}
	}
}

// Tests the metaInfo parsing results
func TestParseMetaInfo(t *testing.T) {
	tests := []struct {
		name, input string
		want        *MetaInfo
	}{
		{
			name: "ParseMetaInfo (all entries, from MNC or before)",
			input: strings.Join([]string{
				`Build: LRX22C`,
				`Build fingerprint: 'google/hammerhead/hammerhead:5.0.1/LRX22C/1602158:user/release-keys'`,
				`Bootloader: HHZ12d`,
				`Radio: msm`,
				`Network: T-Mobile`,
				`...`,
				`[ro.build.id]: [LRX22C]`,
				`[ro.build.version.sdk]: [21]`,
				` [ro.product.model]: [Nexus 5]`, // space intentionally added to make sure it doesn't affect extraction
				`...`,
				`Client:`,
				`  DeviceID: 123456789012345678`,
				`DUMP OF SERVICE sensorservice:`,
				`Sensor List:`,
				`RPR0521 proximity| Rohm      | version=1 |android.sensor.proximity| 0x00000006 | "" | type=8 | on-change | minRate=0.10Hz | maxRate=5.00Hz | FifoMax=300 events | wakeUp | last 10 events = < 1)`,
				`RPR0521 light  | Rohm      | version=1 |android.sensor.light| 0x00000007 | "" | type=5 | on-change | minRate=0.10Hz | maxRate=5.00Hz | no batching | non-wakeUp | last 10 events = < 1)  21.0,  `,
				`BMI160 accelerometer| Bosch     | version=1 |android.sensor.accelerometer| 0x00000001 | "" | type=1 | continuous | minRate=6.25Hz | maxRate=200.00Hz | FifoMax=3000 events | non-wakeUp | last 50 events = < 1)  `,
				`Significant motion| Google    | version=1 |android.sensor.significant_motion| 0x0000000c | "" | type=17 | one-shot | maxDelay=0us |minDelay=-1us |no batching | wakeUp | last 50 events = < 1)   1.0,5267409195000 2`,
			}, "\n"),
			want: &MetaInfo{
				DeviceID:         `123456789012345678`,
				SdkVersion:       21,
				ModelName:        "Nexus 5",
				BuildFingerprint: `google/hammerhead/hammerhead:5.0.1/LRX22C/1602158:user/release-keys`,
				Sensors: map[int32]SensorInfo{
					-10000: {
						Name:   `GPS`,
						Number: -10000,
					},
					6: {
						Name:        `RPR0521 proximity`,
						Type:        `android.sensor.proximity`,
						Number:      6,
						Version:     1,
						RequestMode: `on-change`,
						WakeUp:      true,
						MaxDelay:    10000000,
						MinDelay:    200000,
						Batch:       true,
						Max:         300,
					},
					7: {
						Name:        `RPR0521 light`,
						Type:        `android.sensor.light`,
						Number:      7,
						Version:     1,
						RequestMode: `on-change`,
						WakeUp:      false,
						MaxDelay:    10000000,
						MinDelay:    200000,
						Batch:       false,
					},
					1: {
						Name:        `BMI160 accelerometer`,
						Type:        `android.sensor.accelerometer`,
						Number:      1,
						Version:     1,
						RequestMode: `continuous`,
						WakeUp:      false,
						MaxDelay:    160000,
						MinDelay:    5000,
						Batch:       true,
						Max:         3000,
					},
					12: {
						Name:        `Significant motion`,
						Type:        `android.sensor.significant_motion`,
						Number:      12,
						Version:     1,
						RequestMode: `one-shot`,
						WakeUp:      true,
						MaxDelay:    0,
						MinDelay:    -1,
						Batch:       false,
					},
				},
			},
		},
		{
			name: "ParseMetaInfo (all entries, from NRD42 and onwards)",
			input: strings.Join([]string{
				`Build: LRX22C`,
				`Build fingerprint: 'google/hammerhead/hammerhead:5.0.1/LRX22C/1602158:user/release-keys'`,
				`Bootloader: HHZ12d`,
				`Radio: msm`,
				`Network: T-Mobile`,
				`...`,
				`[ro.build.id]: [LRX22C]`,
				`[ro.build.version.sdk]: [21]`,
				` [ro.product.model]: [Nexus 5]`, // space intentionally added to make sure it doesn't affect extraction
				`...`,
				`Client:`,
				`  DeviceID: 123456789012345678`,
				`DUMP OF SERVICE sensorservice:`,
				`Sensor List:`,
				// The spaces are actually found in bug reports.
				`0000000000) CrosEC Compass            | Google          | ver: 1 | type: android.sensor.magnetic_field(2) | perm: n/a`,
				`	 continuous | minRate=5.00Hz | maxRate=25.00Hz | FIFO (max,reserved) = (1365, 0) events | non-wakeUp | |`,
				`0x00000001) TMD2725 Proximity (wake-up) | AMS             | ver: 1 | type: android.sensor.proximity(8) | perm: n/a | flags: 0x00000003`,
				`on-change | maxDelay=0us | minDelay=0us | FIFO (max,reserved) = (10000, 300) events | wakeUp | `,
				`0x00000002) BMP380 Barometer          | Bosch           | ver: 8709 | type: android.sensor.pressure(6) | perm: n/a | flags: 0x00000000`,
				`continuous | minRate=1.50Hz | maxRate=25.00Hz | FIFO (max,reserved) = (10000, 300) events | non-wakeUp |`,
				`0x00000003) BMP380 Temperature        | Bosch           | ver: 8709 | type: com.google.sensor.pressure_temp(33172003) | perm: n/a | flags: 0x00000000`,
				`continuous | minRate=1.00Hz | maxRate=5.00Hz | FIFO (max,reserved) = (10000, 0) events | non-wakeUp | `,
				`0x00000004) AK0991X Magnetometer Uncalibrated | akm             | ver: 20012 | type: android.sensor.magnetic_field_uncalibrated(14) | perm: n/a | flags: 0x00000880`,
				`continuous | minRate=1.00Hz | maxRate=100.00Hz | FIFO (max,reserved) = (10000, 600) events | non-wakeUp | `,
				`highest rate level = 1, support shared mem: gralloc,`,
				`0x00000005) BMI160 Temperature        | BOSCH           | ver: 1 | type: com.google.sensor.gyro_temperature(33172002) | perm: n/a | flags: 0x00000000`,
				`continuous | minRate=1.00Hz | maxRate=5.00Hz | FIFO (max,reserved) = (10000, 0) events | non-wakeUp | `,
			}, "\n"),
			want: &MetaInfo{
				DeviceID:         `123456789012345678`,
				SdkVersion:       21,
				ModelName:        "Nexus 5",
				BuildFingerprint: `google/hammerhead/hammerhead:5.0.1/LRX22C/1602158:user/release-keys`,
				Sensors: map[int32]SensorInfo{
					-10000: {
						Name:   `GPS`,
						Number: -10000,
					},
					0: {
						Name:        `CrosEC Compass`,
						Type:        `android.sensor.magnetic_field`,
						Number:      0,
						Version:     1,
						RequestMode: `continuous`,
						WakeUp:      false,
						MaxDelay:    200000,
						MinDelay:    40000,
						Batch:       true,
						Max:         1365,
						Reserved:    0,
					},
					1: {
						Name:        `TMD2725 Proximity (wake-up)`,
						Type:        `android.sensor.proximity`,
						Number:      1,
						Version:     1,
						RequestMode: `on-change`,
						WakeUp:      true,
						MaxDelay:    0,
						MinDelay:    0,
						Batch:       true,
						Max:         10000,
						Reserved:    300,
					},
					2: {
						Name:        `BMP380 Barometer`,
						Type:        `android.sensor.pressure`,
						Number:      2,
						Version:     8709,
						RequestMode: `continuous`,
						WakeUp:      false,
						MaxDelay:    666667,
						MinDelay:    40000,
						Batch:       true,
						Max:         10000,
						Reserved:    300,
					},
					3: {
						Name:        `BMP380 Temperature`,
						Type:        `com.google.sensor.pressure_temp`,
						Number:      3,
						Version:     8709,
						RequestMode: `continuous`,
						WakeUp:      false,
						MaxDelay:    1000000,
						MinDelay:    200000,
						Batch:       true,
						Max:         10000,
						Reserved:    0,
					},
					4: {
						Name:        `AK0991X Magnetometer Uncalibrated`,
						Type:        `android.sensor.magnetic_field_uncalibrated`,
						Number:      4,
						Version:     20012,
						RequestMode: `continuous`,
						WakeUp:      false,
						MaxDelay:    1000000,
						MinDelay:    10000,
						Batch:       true,
						Max:         10000,
						Reserved:    600,
					},
					5: {
						Name:        `BMI160 Temperature`,
						Type:        `com.google.sensor.gyro_temperature`,
						Number:      5,
						Version:     1,
						RequestMode: `continuous`,
						WakeUp:      false,
						MaxDelay:    1000000,
						MinDelay:    200000,
						Batch:       true,
						Max:         10000,
						Reserved:    0,
					},
				},
			},
		},
		{
			name: "ParseMetaInfo (without DeviceID)",
			input: strings.Join([]string{
				`Build: LRX22C`,
				`Build fingerprint: 'google/hammerhead/hammerhead:5.0.1/LRX22C/1602158:user/release-keys'`,
				`Bootloader: HHZ12d`,
				`Radio: msm`,
				`Network: T-Mobile`,
				`...`,
				`[ro.build.id]: [LRX22C]`,
				`[ro.build.version.sdk]: [21]`,
				`[ro.product.model]: [Nexus 6]`,
				`...`,
				`Client:`,
			}, "\n"),
			want: &MetaInfo{
				DeviceID:         `not available`,
				SdkVersion:       21,
				ModelName:        "Nexus 6",
				BuildFingerprint: `google/hammerhead/hammerhead:5.0.1/LRX22C/1602158:user/release-keys`,
				Sensors: map[int32]SensorInfo{
					-10000: {Name: `GPS`, Number: -10000},
				},
			},
		},
		{
			name: "ParseMetaInfo with multiple Build fingerprint lines",
			input: strings.Join([]string{
				// From the top of a bug report.
				`Build: shamu-userdebug 6.0 MRA58E 2219288 dev-keys`,
				`Build fingerprint: 'google/shamu/shamu:6.0/MRA58E/2219288:userdebug/dev-keys'`,
				`Bootloader: moto-apq8084-71.15`,
				`Radio: msm`,
				`Network: (unknown)`,
				// There can be multiple instances of the following 3 lines in bug reports,
				// and in some cases, the build fingerprint will not be the correct one.
				`----- pid 10754 at 2015-08-17 01:11:07 -----`,
				`Cmd line: random.package.name`,
				`Build fingerprint: 'google/shamu/shamu:6.0/MRA42/2155602:userdebug/dev-keys'`,
				`...`,
				`[ro.build.id]: [MRA58E]`,
				`[ro.build.version.sdk]: [23]`,
				`[ro.product.model]: [Nexus 6]`,
				`...`,
				`Client:`,
				`  DeviceID: 123456789012345678`,
			}, "\n"),
			want: &MetaInfo{
				DeviceID:         `123456789012345678`,
				SdkVersion:       23,
				ModelName:        "Nexus 6",
				BuildFingerprint: `google/shamu/shamu:6.0/MRA58E/2219288:userdebug/dev-keys`,
				Sensors: map[int32]SensorInfo{
					-10000: {Name: `GPS`, Number: -10000},
				},
			},
		},
		{
			name: "ParseMetaInfo (repeated information for the same sensor)",
			input: strings.Join([]string{
				`Build: LRX22C`,
				`Build fingerprint: 'google/hammerhead/hammerhead:5.0.1/LRX22C/1602158:user/release-keys'`,
				`Bootloader: HHZ12d`,
				`Radio: msm`,
				`Network: T-Mobile`,
				`...`,
				`[ro.build.id]: [LRX22C]`,
				`[ro.build.version.sdk]: [21]`,
				` [ro.product.model]: [Nexus 5]`,
				// space intentionally added to make sure it doesn't affect extraction
				`...`,
				`Client:`,
				`  DeviceID: 123456789012345678`,
				`DUMP OF SERVICE sensorservice:`,
				`Sensor List:`,
				// The spaces are actually found in bug reports.
				// Format as of NRD42C. Sensor 0 doesn't have 0x.
				`0x00000001) TMD2725 Proximity (wake-up) | AMS             | ver: 1 | type: android.sensor.proximity(8) | perm: n/a | flags: 0x00000003`,
				`on-change | maxDelay=100us | minDelay=0us | FIFO (max,reserved) = (111, 300) events | wakeUp | `,
				`0x00000001) TMD2725 Proximity (wake-up) | AMS             | ver: 10086 | type: android.sensor.light(8) | perm: n/a | flags: 0x00000003`,
				`on-change | maxDelay=0us | minDelay=70us | FIFO (max,reserved) = (10000, 300) events | wakeUp | `,
				`0x00000001) TMD2725 Proximity (wake-up) | AMS             | ver: 1 | type: android.sensor.proximity(8) | perm: n/a | flags: 0x00000003`,
				`on-change | maxDelay=0us | minDelay=0us | FIFO (max,reserved) = (10000, 300) events | wakeUp | `,
			}, "\n"),
			want: &MetaInfo{
				DeviceID:         `123456789012345678`,
				SdkVersion:       21,
				ModelName:        "Nexus 5",
				BuildFingerprint: `google/hammerhead/hammerhead:5.0.1/LRX22C/1602158:user/release-keys`,
				Sensors: map[int32]SensorInfo{
					-10000: {
						Name:   `GPS`,
						Number: -10000,
					},
					1: {
						Name:        `TMD2725 Proximity (wake-up)`,
						Type:        `android.sensor.proximity`,
						Number:      1,
						Version:     1,
						RequestMode: `on-change`,
						WakeUp:      true,
						MaxDelay:    0,
						MinDelay:    0,
						Batch:       true,
						Max:         10000,
						Reserved:    300,
					},
				},
			},
		},
		{
			name: "ParseMetaInfo (all entries with CRITICAL sensorservice, from NRD42 and onwards)",
			input: strings.Join([]string{
				`Build: LRX22C`,
				`Build fingerprint: 'google/hammerhead/hammerhead:5.0.1/LRX22C/1602158:user/release-keys'`,
				`Bootloader: HHZ12d`,
				`Radio: msm`,
				`Network: T-Mobile`,
				`...`,
				`[ro.build.id]: [LRX22C]`,
				`[ro.build.version.sdk]: [21]`,
				` [ro.product.model]: [Nexus 5]`, // space intentionally added to make sure it doesn't affect extraction
				`...`,
				`Client:`,
				`  DeviceID: 123456789012345678`,
				`DUMP OF SERVICE CRITICAL sensorservice:`,
				`Sensor List:`,
				// The spaces are actually found in bug reports.
				`0x00000001) TMD2725 Proximity (wake-up) | AMS             | ver: 1 | type: android.sensor.proximity(8) | perm: n/a | flags: 0x00000003`,
				`on-change | maxDelay=0us | minDelay=0us | FIFO (max,reserved) = (10000, 300) events | wakeUp | `,
				`0x00000002) BMP380 Barometer          | Bosch           | ver: 8709 | type: android.sensor.pressure(6) | perm: n/a | flags: 0x00000000`,
				`continuous | minRate=1.00Hz | maxRate=25.00Hz | FIFO (max,reserved) = (10000, 300) events | non-wakeUp |`,
			}, "\n"),
			want: &MetaInfo{
				DeviceID:         `123456789012345678`,
				SdkVersion:       21,
				ModelName:        "Nexus 5",
				BuildFingerprint: `google/hammerhead/hammerhead:5.0.1/LRX22C/1602158:user/release-keys`,
				Sensors: map[int32]SensorInfo{
					-10000: {
						Name:   `GPS`,
						Number: -10000,
					},
					1: {
						Name:        `TMD2725 Proximity (wake-up)`,
						Type:        `android.sensor.proximity`,
						Number:      1,
						Version:     1,
						RequestMode: `on-change`,
						WakeUp:      true,
						MaxDelay:    0,
						MinDelay:    0,
						Batch:       true,
						Max:         10000,
						Reserved:    300,
					},
					2: {
						Name:        `BMP380 Barometer`,
						Type:        `android.sensor.pressure`,
						Number:      2,
						Version:     8709,
						RequestMode: `continuous`,
						WakeUp:      false,
						MaxDelay:    1000000,
						MinDelay:    40000,
						Batch:       true,
						Max:         10000,
						Reserved:    300,
					},
				},
			},
		},
	}

	for _, test := range tests {
		meta, err := ParseMetaInfo(test.input)
		if err != nil {
			t.Errorf("%v: error: %q", test.name, err)
		}
		if !reflect.DeepEqual(meta, test.want) {
			t.Errorf("%v:\n  got: %v\n  want: %v", test.name, meta, test.want)
		}
	}
}

// Tests getting the PID to app mapping.
func TestExtractPIDMappings(t *testing.T) {
	tests := []struct {
		desc         string
		input        []string
		want         map[string][]AppInfo
		wantWarnings []string
	}{
		{
			desc: "Various PID mappings",
			input: []string{
				`  PID mappings:`,
				`    PID #659: ProcessRecord{9b4f852 659:com.motorola.targetnotif/u0a124}`,
				`    PID #1422: ProcessRecord{96225d2 1422:com.google.android.apps.shopping.express/u0a183}`,
				`    PID #1805: ProcessRecord{e2a1678 1805:com.facebook.katana/u0a157}`,
			},
			want: map[string][]AppInfo{
				"659": {
					{
						Name: "com.motorola.targetnotif",
						UID:  "10124",
					},
				},
				"1422": {
					{
						Name: "com.google.android.apps.shopping.express",
						UID:  "10183",
					},
				},
				"1805": {
					{
						Name: "com.facebook.katana",
						UID:  "10157",
					},
				},
			},
		},
		{
			desc: "Duplicated mapping",
			input: []string{
				`  PID mappings:`,
				`    PID #659: ProcessRecord{9b4f852 659:com.motorola.targetnotif/u0a124}`,
				`    PID #659: ProcessRecord{96225d2 659:com.google.android.apps.shopping.express/u0a183}`,
			},
			want: map[string][]AppInfo{
				"659": {
					{
						Name: "com.motorola.targetnotif",
						UID:  "10124",
					},
					{
						Name: "com.google.android.apps.shopping.express",
						UID:  "10183",
					},
				},
			},
		},
		{
			desc: "Warnings",
			input: []string{
				`  PID mappings:`,
				`    PID #659: ProcessRecord{9b4f852 659:com.motorola.targetnotif/invaliduid}`,
			},
			want: map[string][]AppInfo{
				"659": {
					{
						Name: "com.motorola.targetnotif",
					},
				},
			},
			wantWarnings: []string{"invalid uid: invaliduid"},
		},
	}
	for _, test := range tests {
		pm, warns := ExtractPIDMappings(strings.Join(test.input, "\n"))
		if !reflect.DeepEqual(pm, test.want) {
			t.Errorf("%v--ExtractPIDMappings(%v):\n  got: %v\n  want: %v", test.desc, test.input, pm, test.want)
		}
		if !reflect.DeepEqual(warns, test.wantWarnings) {
			t.Errorf("%v--ExtractPIDMappings(%v):\n  got warnings: %v\n  want: %v", test.desc, test.input, warns, test.wantWarnings)
		}
	}
}
