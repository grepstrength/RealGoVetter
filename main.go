/*
Copyright (c) 2024 Kelvin Winborne (aka. "grepStrength")

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/VirusTotal/vt-go"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

type IOCResult struct { //this is the structure for the results of the VirusTotal API check
	IOC            string
	ThreatCategory string
	Malicious      int64
	Suspicious     int64
	Clean          int64
	Unknown        int64
}

var progressBar *widget.ProgressBar //pointer to the progress bar and label to show the progress of the current IOC being processed
var progressLabel *widget.Label

type VTResponse struct { //this is the VirusTotal response structure for the API check's results
	ResponseCode int                   `json:"response_code"`
	Positives    int                   `json:"positives"`
	Total        int                   `json:"total"`
	Scans        map[string]ScanResult `json:"scans"`
	Resource     string                `json:"resource"`
	Message      string                `json:"verbose_msg"`
}

type ScanResult struct {
	Detected bool   `json:"detected"`
	Result   string `json:"result"`
}

var ( //these are the Windows API functions to hide the console window when the application is run
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	user32               = syscall.NewLazyDLL("user32.dll")
	procShowWindow       = user32.NewProc("ShowWindow")
)

func hideConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, 0)
	}
}
func main() {
	hideConsoleWindow()
	a := app.New()
	w := a.NewWindow("RealGoVetter") //creates a window and sets the window title to "RealGoVetter"
	apiKey := loadAPIKey()

	//creates the window with the API key entry field, save button, and select file button
	apiKeyEntry := widget.NewPasswordEntry()
	if apiKey != "" {
		apiKeyEntry.SetText(apiKey)
	}
	//creates the progress bar and label to show the progress of the current IOC being processed
	progressBar = widget.NewProgressBar()
	progressLabel = widget.NewLabel("")
	progressBar.Hide()
	progressLabel.Hide()

	results := make([]IOCResult, 0)

	saveAPIBtn := widget.NewButton("Save API Key", func() { //this is always saved in "C:\Users\<USERNAME>\AppData\Roaming\RealGoVetter\config.dat"
		saveAPIKey(apiKeyEntry.Text)
		dialog.ShowInformation("Success", "API Key Saved", w)
	})

	selectFileBtn := widget.NewButton("Select IOC File", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return
			}

			go processIOCs(reader, apiKeyEntry.Text, &results, w) //runs the processIOCs function in a separate goroutine to prevent the UI from freezing
		}, w)
	})

	content := container.NewVBox(
		widget.NewLabel("VirusTotal API Key:"),
		apiKeyEntry,
		saveAPIBtn,
		selectFileBtn,
		progressBar,
		progressLabel,
	)

	w.SetContent(content)
	w.Resize(fyne.NewSize(800, 800)) //sets and keeps the window size to 800x800 pixels to make it easier to read the results
	w.ShowAndRun()
}

func processIOCs(reader fyne.URIReadCloser, apiKey string, results *[]IOCResult, window fyne.Window) {
	progressBar.Show()
	progressLabel.Show()

	data, err := ioutil.ReadAll(reader) //reads the data from the file loaded by the user
	if err != nil {
		dialog.ShowError(err, window)
		return
	}

	lines := strings.Split(string(data), "\n") //splits the data into lines based on the newline character
	validLines := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			validLines++
		}
	}

	progressBar.Max = float64(validLines) //sets the maximum value of the progress bar to the number of valid lines in the file
	progressBar.Value = 0
	outputFile := "results_" + time.Now().Format("20060102150405") + ".csv" //automatically sets the output file name to include the current date and time

	csvFile, err := os.Create(outputFile)
	if err != nil {
		dialog.ShowError(err, window)
		return
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	// Write header
	writer.Write([]string{"IOC", "Threat Category", "Malicious", "Suspicious", "Clean", "Unknown"})
	for i, line := range lines {
		ioc := strings.TrimSpace(line)
		if ioc == "" {
			continue
		}

		progressLabel.SetText(fmt.Sprintf("Processing: %s", ioc)) //shows the progress of the current IOC being processed
		result := checkVirusTotal(ioc, apiKey)
		*results = append(*results, result)
		writer.Write([]string{
			result.IOC,
			result.ThreatCategory,
			fmt.Sprintf("%d", result.Malicious),
			fmt.Sprintf("%d", result.Suspicious),
			fmt.Sprintf("%d", result.Clean),
			fmt.Sprintf("%d", result.Unknown),
		})
		progressBar.SetValue(float64(i + 1))
	}

	progressBar.Hide()
	progressLabel.Hide()
	dialog.ShowInformation("Complete", "Analysis completed. Results saved to "+outputFile, window) //saves the results to a CSV file in the same directory as the executable
}

func checkVirusTotal(ioc string, apiKey string) IOCResult {
	client := vt.NewClient(apiKey)

	fileObj, err := client.GetObject(vt.URL(fmt.Sprintf("files/%s", ioc)))
	if err == nil {
		malicious, _ := fileObj.GetInt64("last_analysis_stats.malicious")
		suspicious, _ := fileObj.GetInt64("last_analysis_stats.suspicious")
		clean, _ := fileObj.GetInt64("last_analysis_stats.undetected")
		unknown, _ := fileObj.GetInt64("last_analysis_stats.type_unsupported")
		category, _ := fileObj.GetString("type_description")

		return IOCResult{
			IOC:            ioc,
			ThreatCategory: category, //basically "Domain" or "IP Address" or "URL" depending on the context
			Malicious:      malicious,
			Suspicious:     suspicious,
			Clean:          clean,
			Unknown:        unknown,
		}
	}

	urlObj, err := client.GetObject(vt.URL(fmt.Sprintf("urls/%s", ioc)))
	if err == nil {
		malicious, _ := urlObj.GetInt64("last_analysis_stats.malicious")
		suspicious, _ := urlObj.GetInt64("last_analysis_stats.suspicious")
		clean, _ := urlObj.GetInt64("last_analysis_stats.undetected")
		unknown, _ := urlObj.GetInt64("last_analysis_stats.type_unsupported")

		return IOCResult{
			IOC:            ioc,
			ThreatCategory: "URL",
			Malicious:      malicious,
			Suspicious:     suspicious,
			Clean:          clean,
			Unknown:        unknown,
		}
	}

	domainObj, err := client.GetObject(vt.URL(fmt.Sprintf("domains/%s", ioc)))
	if err == nil {
		malicious, _ := domainObj.GetInt64("last_analysis_stats.malicious")
		suspicious, _ := domainObj.GetInt64("last_analysis_stats.suspicious")
		clean, _ := domainObj.GetInt64("last_analysis_stats.undetected")
		unknown, _ := domainObj.GetInt64("last_analysis_stats.type_unsupported")

		return IOCResult{
			IOC:            ioc,
			ThreatCategory: "Domain",
			Malicious:      malicious,
			Suspicious:     suspicious,
			Clean:          clean,
			Unknown:        unknown,
		}
	}

	ipObj, err := client.GetObject(vt.URL(fmt.Sprintf("ip_addresses/%s", ioc)))
	if err == nil {
		malicious, _ := ipObj.GetInt64("last_analysis_stats.malicious")
		suspicious, _ := ipObj.GetInt64("last_analysis_stats.suspicious")
		clean, _ := ipObj.GetInt64("last_analysis_stats.undetected")
		unknown, _ := ipObj.GetInt64("last_analysis_stats.type_unsupported")

		return IOCResult{
			IOC:            ioc,
			ThreatCategory: "IP Address",
			//DetectionRatio: fmt.Sprintf("%d/%d", malicious+suspicious, total), //removed because the "10/0" kept getting represented as MON-YR (eg "Oct-00") in Excel
			Malicious:  malicious,
			Suspicious: suspicious,
			Clean:      clean,
			Unknown:    unknown,
		}
	}

	return IOCResult{
		IOC:            ioc,
		ThreatCategory: "Not Found",
		//DetectionRatio: "0/0", //removed because the "10/0" kept getting represented as MON-YR (eg "Oct-00") in Excel
		Malicious:  0,
		Suspicious: 0,
		Clean:      0,
		Unknown:    0,
	}
}

func getConfigPath() string {
	appData, err := os.UserConfigDir()
	if err != nil {
		appData = "."
	}
	return filepath.Join(appData, "RealGoVetter")
}

func saveAPIKey(key string) {
	configDir := getConfigPath()
	os.MkdirAll(configDir, 0700)
	configFile := filepath.Join(configDir, "config.dat") //this is always saved in "C:\Users\<USERNAME>\AppData\Roaming\RealGoVetter\config.dat" as a hidden file with the API key base64 encoded

	encoded := base64.StdEncoding.EncodeToString([]byte(key))
	ioutil.WriteFile(configFile, []byte(encoded), 0600)

	//sets the config.dat file to be hidden
	configFileUTF16, err := syscall.UTF16PtrFromString(configFile)
	if err == nil {
		syscall.SetFileAttributes(configFileUTF16, syscall.FILE_ATTRIBUTE_HIDDEN)
	}
}

func loadAPIKey() string { //this function loads the API key from the saved config.dat file
	configFile := filepath.Join(getConfigPath(), "config.dat")
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return ""
	}
	return string(decoded)
}
