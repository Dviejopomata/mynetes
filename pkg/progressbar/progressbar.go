package progressbar

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gosuri/uilive"
	"io"
)

type Message struct {
	Message  string
	Progress int64
	Done     bool
}

type IStep interface {
	Done()
	Error(err error)
}

type Step struct {
	Message string
	Writer  io.Writer
}

func (s *Step) Done() {
	if w, ok := s.Writer.(*uilive.Writer); ok {
		fmt.Fprintf(w.Bypass(), "")
	}
}
func (s *Step) Error(err error) {
	fmt.Fprintf(s.Writer, err.Error())
}

type HttpStep struct {
	Message string
	Writer  gin.ResponseWriter
}

func (s HttpStep) Done() {
	msg := &Message{Message: s.Message, Done: true}
	b, _ := json.Marshal(msg)
	b = append(b, []byte("\n")...)
	s.Writer.Write(b)
	s.Writer.Flush()

}
func (s HttpStep) Error(err error) {
	fmt.Fprintf(s.Writer, err.Error())
}

type IProgressBar interface {
	NewStep(message string) IStep
	Error(err error)
	Finish()
}

type ProgressBar struct {
	Writer io.Writer
}

type HttpProgressBar struct {
	Writer gin.ResponseWriter
}

func (p HttpProgressBar) Finish() {

}
func (p HttpProgressBar) NewStep(message string) IStep {
	step := HttpStep{Message: message, Writer: p.Writer}
	msg := &Message{Message: message}
	b, _ := json.Marshal(msg)
	b = append(b, []byte("\n")...)
	p.Writer.Write(b)
	p.Writer.Flush()
	return step
}

func (p HttpProgressBar) Error(err error) {
	fmt.Fprintf(p.Writer, err.Error())

}

func NewHttpProgressBar(w gin.ResponseWriter) HttpProgressBar {
	return HttpProgressBar{
		Writer: w,
	}
}

func NewCliProgressBar() *ProgressBar {
	writer := uilive.New()
	writer.Start()
	return &ProgressBar{
		Writer: writer,
	}
}
func (p *ProgressBar) Finish() {
	if w, ok := p.Writer.(*uilive.Writer); ok {
		w.Stop()
	}
}
func (p *ProgressBar) NewStep(message string) Step {
	step := Step{Message: message, Writer: p.Writer}
	fmt.Fprintf(p.Writer, message)
	return step
}

func (p *ProgressBar) Error(err error) {
	fmt.Fprintf(p.Writer, err.Error())
}
