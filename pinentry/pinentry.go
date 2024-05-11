package pinentry

import (
	"errors"
	"os/exec"
	"sync"
	"time"

	"github.com/twpayne/go-pinentry/v4"
)

func New() *Pinentry {
	return &Pinentry{}
}

type Pinentry struct {
	mu            sync.Mutex
	activeRequest *request
}

type request struct {
	timeout       time.Duration
	pendingResult chan Result
	extendTimeout chan time.Duration

	challengeParam   [32]byte
	applicationParam [32]byte
}

type Result struct {
	OK    bool
	Error error
}

func (pe *Pinentry) ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan Result, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	timeout := 2 * time.Second

	if pe.activeRequest != nil {
		if challengeParam != pe.activeRequest.challengeParam || applicationParam != pe.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		extendTimeoutChan := pe.activeRequest.extendTimeout

		go func() {
			select {
			case extendTimeoutChan <- timeout:
			case <-time.After(timeout):
			}
		}()

		return pe.activeRequest.pendingResult, nil
	}

	pe.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		pendingResult:    make(chan Result),
		extendTimeout:    make(chan time.Duration),
	}

	go pe.prompt(pe.activeRequest, prompt)

	return pe.activeRequest.pendingResult, nil
}

func (pe *Pinentry) prompt(req *request, prompt string) {
	sendResult := func(r Result) {
		select {
		case req.pendingResult <- r:
		case <-time.After(req.timeout):
			// we expect requests to come in every ~750ms.
			// If we've been waiting for 2 seconds the client
			// is likely gone.
		}

		pe.mu.Lock()
		pe.activeRequest = nil
		pe.mu.Unlock()
	}
	binary := FindPinentryGUIPath()
	client, err := pinentry.NewClient(
		pinentry.WithBinaryName(binary),
		pinentry.WithDesc(prompt),
		pinentry.WithTitle("TPM-FIDO"),
		pinentry.WithPrompt("TPM-FIDO"),
	)
	if err != nil {
		sendResult(Result{Error: err})
		return
	}
	defer client.Close()
	confirmed, err := client.Confirm(prompt)

	if err != nil {
		sendResult(Result{Error: err})
		return
	}

	promptResult := make(chan bool)

	go func() {
		promptResult <- confirmed
	}()

	timer := time.NewTimer(req.timeout)

	for {
		select {
		case ok := <-promptResult:
			sendResult(Result{
				OK: ok,
			})
			return
		case <-timer.C:
			sendResult(Result{
				OK:    false,
				Error: errors.New("request timed out"),
			})
			return
		case d := <-req.extendTimeout:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(d)
		}
	}

}

func FindPinentryGUIPath() string {
	candidates := []string{
		"pinentry-gnome3",
		"pinentry-qt5",
		"pinentry-qt4",
		"pinentry-qt",
		"pinentry-gtk-2",
		"pinentry-x11",
		"pinentry-fltk",
	}
	for _, candidate := range candidates {
		p, _ := exec.LookPath(candidate)
		if p != "" {
			return p
		}
	}
	return ""
}
