package crypt

// Code generated by http://github.com/gojuno/minimock (dev). DO NOT EDIT.

import (
	"sync"
	mm_atomic "sync/atomic"
	mm_time "time"

	"github.com/gojuno/minimock/v3"
)

// EncrypterMock implements Encrypter
type EncrypterMock struct {
	t minimock.Tester

	funcDecrypt          func(encrypted []byte) (ba1 []byte, err error)
	inspectFuncDecrypt   func(encrypted []byte)
	afterDecryptCounter  uint64
	beforeDecryptCounter uint64
	DecryptMock          mEncrypterMockDecrypt

	funcEncrypt          func(plain []byte) (ba1 []byte, err error)
	inspectFuncEncrypt   func(plain []byte)
	afterEncryptCounter  uint64
	beforeEncryptCounter uint64
	EncryptMock          mEncrypterMockEncrypt
}

// NewEncrypterMock returns a mock for Encrypter
func NewEncrypterMock(t minimock.Tester) *EncrypterMock {
	m := &EncrypterMock{t: t}
	if controller, ok := t.(minimock.MockController); ok {
		controller.RegisterMocker(m)
	}

	m.DecryptMock = mEncrypterMockDecrypt{mock: m}
	m.DecryptMock.callArgs = []*EncrypterMockDecryptParams{}

	m.EncryptMock = mEncrypterMockEncrypt{mock: m}
	m.EncryptMock.callArgs = []*EncrypterMockEncryptParams{}

	return m
}

type mEncrypterMockDecrypt struct {
	mock               *EncrypterMock
	defaultExpectation *EncrypterMockDecryptExpectation
	expectations       []*EncrypterMockDecryptExpectation

	callArgs []*EncrypterMockDecryptParams
	mutex    sync.RWMutex
}

// EncrypterMockDecryptExpectation specifies expectation struct of the Encrypter.Decrypt
type EncrypterMockDecryptExpectation struct {
	mock    *EncrypterMock
	params  *EncrypterMockDecryptParams
	results *EncrypterMockDecryptResults
	Counter uint64
}

// EncrypterMockDecryptParams contains parameters of the Encrypter.Decrypt
type EncrypterMockDecryptParams struct {
	encrypted []byte
}

// EncrypterMockDecryptResults contains results of the Encrypter.Decrypt
type EncrypterMockDecryptResults struct {
	ba1 []byte
	err error
}

// Expect sets up expected params for Encrypter.Decrypt
func (mmDecrypt *mEncrypterMockDecrypt) Expect(encrypted []byte) *mEncrypterMockDecrypt {
	if mmDecrypt.mock.funcDecrypt != nil {
		mmDecrypt.mock.t.Fatalf("EncrypterMock.Decrypt mock is already set by Set")
	}

	if mmDecrypt.defaultExpectation == nil {
		mmDecrypt.defaultExpectation = &EncrypterMockDecryptExpectation{}
	}

	mmDecrypt.defaultExpectation.params = &EncrypterMockDecryptParams{encrypted}
	for _, e := range mmDecrypt.expectations {
		if minimock.Equal(e.params, mmDecrypt.defaultExpectation.params) {
			mmDecrypt.mock.t.Fatalf("Expectation set by When has same params: %#v", *mmDecrypt.defaultExpectation.params)
		}
	}

	return mmDecrypt
}

// Inspect accepts an inspector function that has same arguments as the Encrypter.Decrypt
func (mmDecrypt *mEncrypterMockDecrypt) Inspect(f func(encrypted []byte)) *mEncrypterMockDecrypt {
	if mmDecrypt.mock.inspectFuncDecrypt != nil {
		mmDecrypt.mock.t.Fatalf("Inspect function is already set for EncrypterMock.Decrypt")
	}

	mmDecrypt.mock.inspectFuncDecrypt = f

	return mmDecrypt
}

// Return sets up results that will be returned by Encrypter.Decrypt
func (mmDecrypt *mEncrypterMockDecrypt) Return(ba1 []byte, err error) *EncrypterMock {
	if mmDecrypt.mock.funcDecrypt != nil {
		mmDecrypt.mock.t.Fatalf("EncrypterMock.Decrypt mock is already set by Set")
	}

	if mmDecrypt.defaultExpectation == nil {
		mmDecrypt.defaultExpectation = &EncrypterMockDecryptExpectation{mock: mmDecrypt.mock}
	}
	mmDecrypt.defaultExpectation.results = &EncrypterMockDecryptResults{ba1, err}
	return mmDecrypt.mock
}

//Set uses given function f to mock the Encrypter.Decrypt method
func (mmDecrypt *mEncrypterMockDecrypt) Set(f func(encrypted []byte) (ba1 []byte, err error)) *EncrypterMock {
	if mmDecrypt.defaultExpectation != nil {
		mmDecrypt.mock.t.Fatalf("Default expectation is already set for the Encrypter.Decrypt method")
	}

	if len(mmDecrypt.expectations) > 0 {
		mmDecrypt.mock.t.Fatalf("Some expectations are already set for the Encrypter.Decrypt method")
	}

	mmDecrypt.mock.funcDecrypt = f
	return mmDecrypt.mock
}

// When sets expectation for the Encrypter.Decrypt which will trigger the result defined by the following
// Then helper
func (mmDecrypt *mEncrypterMockDecrypt) When(encrypted []byte) *EncrypterMockDecryptExpectation {
	if mmDecrypt.mock.funcDecrypt != nil {
		mmDecrypt.mock.t.Fatalf("EncrypterMock.Decrypt mock is already set by Set")
	}

	expectation := &EncrypterMockDecryptExpectation{
		mock:   mmDecrypt.mock,
		params: &EncrypterMockDecryptParams{encrypted},
	}
	mmDecrypt.expectations = append(mmDecrypt.expectations, expectation)
	return expectation
}

// Then sets up Encrypter.Decrypt return parameters for the expectation previously defined by the When method
func (e *EncrypterMockDecryptExpectation) Then(ba1 []byte, err error) *EncrypterMock {
	e.results = &EncrypterMockDecryptResults{ba1, err}
	return e.mock
}

// Decrypt implements Encrypter
func (mmDecrypt *EncrypterMock) Decrypt(encrypted []byte) (ba1 []byte, err error) {
	mm_atomic.AddUint64(&mmDecrypt.beforeDecryptCounter, 1)
	defer mm_atomic.AddUint64(&mmDecrypt.afterDecryptCounter, 1)

	if mmDecrypt.inspectFuncDecrypt != nil {
		mmDecrypt.inspectFuncDecrypt(encrypted)
	}

	mm_params := &EncrypterMockDecryptParams{encrypted}

	// Record call args
	mmDecrypt.DecryptMock.mutex.Lock()
	mmDecrypt.DecryptMock.callArgs = append(mmDecrypt.DecryptMock.callArgs, mm_params)
	mmDecrypt.DecryptMock.mutex.Unlock()

	for _, e := range mmDecrypt.DecryptMock.expectations {
		if minimock.Equal(e.params, mm_params) {
			mm_atomic.AddUint64(&e.Counter, 1)
			return e.results.ba1, e.results.err
		}
	}

	if mmDecrypt.DecryptMock.defaultExpectation != nil {
		mm_atomic.AddUint64(&mmDecrypt.DecryptMock.defaultExpectation.Counter, 1)
		mm_want := mmDecrypt.DecryptMock.defaultExpectation.params
		mm_got := EncrypterMockDecryptParams{encrypted}
		if mm_want != nil && !minimock.Equal(*mm_want, mm_got) {
			mmDecrypt.t.Errorf("EncrypterMock.Decrypt got unexpected parameters, want: %#v, got: %#v%s\n", *mm_want, mm_got, minimock.Diff(*mm_want, mm_got))
		}

		mm_results := mmDecrypt.DecryptMock.defaultExpectation.results
		if mm_results == nil {
			mmDecrypt.t.Fatal("No results are set for the EncrypterMock.Decrypt")
		}
		return (*mm_results).ba1, (*mm_results).err
	}
	if mmDecrypt.funcDecrypt != nil {
		return mmDecrypt.funcDecrypt(encrypted)
	}
	mmDecrypt.t.Fatalf("Unexpected call to EncrypterMock.Decrypt. %v", encrypted)
	return
}

// DecryptAfterCounter returns a count of finished EncrypterMock.Decrypt invocations
func (mmDecrypt *EncrypterMock) DecryptAfterCounter() uint64 {
	return mm_atomic.LoadUint64(&mmDecrypt.afterDecryptCounter)
}

// DecryptBeforeCounter returns a count of EncrypterMock.Decrypt invocations
func (mmDecrypt *EncrypterMock) DecryptBeforeCounter() uint64 {
	return mm_atomic.LoadUint64(&mmDecrypt.beforeDecryptCounter)
}

// Calls returns a list of arguments used in each call to EncrypterMock.Decrypt.
// The list is in the same order as the calls were made (i.e. recent calls have a higher index)
func (mmDecrypt *mEncrypterMockDecrypt) Calls() []*EncrypterMockDecryptParams {
	mmDecrypt.mutex.RLock()

	argCopy := make([]*EncrypterMockDecryptParams, len(mmDecrypt.callArgs))
	copy(argCopy, mmDecrypt.callArgs)

	mmDecrypt.mutex.RUnlock()

	return argCopy
}

// MinimockDecryptDone returns true if the count of the Decrypt invocations corresponds
// the number of defined expectations
func (m *EncrypterMock) MinimockDecryptDone() bool {
	for _, e := range m.DecryptMock.expectations {
		if mm_atomic.LoadUint64(&e.Counter) < 1 {
			return false
		}
	}

	// if default expectation was set then invocations count should be greater than zero
	if m.DecryptMock.defaultExpectation != nil && mm_atomic.LoadUint64(&m.afterDecryptCounter) < 1 {
		return false
	}
	// if func was set then invocations count should be greater than zero
	if m.funcDecrypt != nil && mm_atomic.LoadUint64(&m.afterDecryptCounter) < 1 {
		return false
	}
	return true
}

// MinimockDecryptInspect logs each unmet expectation
func (m *EncrypterMock) MinimockDecryptInspect() {
	for _, e := range m.DecryptMock.expectations {
		if mm_atomic.LoadUint64(&e.Counter) < 1 {
			m.t.Errorf("Expected call to EncrypterMock.Decrypt with params: %#v", *e.params)
		}
	}

	// if default expectation was set then invocations count should be greater than zero
	if m.DecryptMock.defaultExpectation != nil && mm_atomic.LoadUint64(&m.afterDecryptCounter) < 1 {
		if m.DecryptMock.defaultExpectation.params == nil {
			m.t.Error("Expected call to EncrypterMock.Decrypt")
		} else {
			m.t.Errorf("Expected call to EncrypterMock.Decrypt with params: %#v", *m.DecryptMock.defaultExpectation.params)
		}
	}
	// if func was set then invocations count should be greater than zero
	if m.funcDecrypt != nil && mm_atomic.LoadUint64(&m.afterDecryptCounter) < 1 {
		m.t.Error("Expected call to EncrypterMock.Decrypt")
	}
}

type mEncrypterMockEncrypt struct {
	mock               *EncrypterMock
	defaultExpectation *EncrypterMockEncryptExpectation
	expectations       []*EncrypterMockEncryptExpectation

	callArgs []*EncrypterMockEncryptParams
	mutex    sync.RWMutex
}

// EncrypterMockEncryptExpectation specifies expectation struct of the Encrypter.Encrypt
type EncrypterMockEncryptExpectation struct {
	mock    *EncrypterMock
	params  *EncrypterMockEncryptParams
	results *EncrypterMockEncryptResults
	Counter uint64
}

// EncrypterMockEncryptParams contains parameters of the Encrypter.Encrypt
type EncrypterMockEncryptParams struct {
	plain []byte
}

// EncrypterMockEncryptResults contains results of the Encrypter.Encrypt
type EncrypterMockEncryptResults struct {
	ba1 []byte
	err error
}

// Expect sets up expected params for Encrypter.Encrypt
func (mmEncrypt *mEncrypterMockEncrypt) Expect(plain []byte) *mEncrypterMockEncrypt {
	if mmEncrypt.mock.funcEncrypt != nil {
		mmEncrypt.mock.t.Fatalf("EncrypterMock.Encrypt mock is already set by Set")
	}

	if mmEncrypt.defaultExpectation == nil {
		mmEncrypt.defaultExpectation = &EncrypterMockEncryptExpectation{}
	}

	mmEncrypt.defaultExpectation.params = &EncrypterMockEncryptParams{plain}
	for _, e := range mmEncrypt.expectations {
		if minimock.Equal(e.params, mmEncrypt.defaultExpectation.params) {
			mmEncrypt.mock.t.Fatalf("Expectation set by When has same params: %#v", *mmEncrypt.defaultExpectation.params)
		}
	}

	return mmEncrypt
}

// Inspect accepts an inspector function that has same arguments as the Encrypter.Encrypt
func (mmEncrypt *mEncrypterMockEncrypt) Inspect(f func(plain []byte)) *mEncrypterMockEncrypt {
	if mmEncrypt.mock.inspectFuncEncrypt != nil {
		mmEncrypt.mock.t.Fatalf("Inspect function is already set for EncrypterMock.Encrypt")
	}

	mmEncrypt.mock.inspectFuncEncrypt = f

	return mmEncrypt
}

// Return sets up results that will be returned by Encrypter.Encrypt
func (mmEncrypt *mEncrypterMockEncrypt) Return(ba1 []byte, err error) *EncrypterMock {
	if mmEncrypt.mock.funcEncrypt != nil {
		mmEncrypt.mock.t.Fatalf("EncrypterMock.Encrypt mock is already set by Set")
	}

	if mmEncrypt.defaultExpectation == nil {
		mmEncrypt.defaultExpectation = &EncrypterMockEncryptExpectation{mock: mmEncrypt.mock}
	}
	mmEncrypt.defaultExpectation.results = &EncrypterMockEncryptResults{ba1, err}
	return mmEncrypt.mock
}

//Set uses given function f to mock the Encrypter.Encrypt method
func (mmEncrypt *mEncrypterMockEncrypt) Set(f func(plain []byte) (ba1 []byte, err error)) *EncrypterMock {
	if mmEncrypt.defaultExpectation != nil {
		mmEncrypt.mock.t.Fatalf("Default expectation is already set for the Encrypter.Encrypt method")
	}

	if len(mmEncrypt.expectations) > 0 {
		mmEncrypt.mock.t.Fatalf("Some expectations are already set for the Encrypter.Encrypt method")
	}

	mmEncrypt.mock.funcEncrypt = f
	return mmEncrypt.mock
}

// When sets expectation for the Encrypter.Encrypt which will trigger the result defined by the following
// Then helper
func (mmEncrypt *mEncrypterMockEncrypt) When(plain []byte) *EncrypterMockEncryptExpectation {
	if mmEncrypt.mock.funcEncrypt != nil {
		mmEncrypt.mock.t.Fatalf("EncrypterMock.Encrypt mock is already set by Set")
	}

	expectation := &EncrypterMockEncryptExpectation{
		mock:   mmEncrypt.mock,
		params: &EncrypterMockEncryptParams{plain},
	}
	mmEncrypt.expectations = append(mmEncrypt.expectations, expectation)
	return expectation
}

// Then sets up Encrypter.Encrypt return parameters for the expectation previously defined by the When method
func (e *EncrypterMockEncryptExpectation) Then(ba1 []byte, err error) *EncrypterMock {
	e.results = &EncrypterMockEncryptResults{ba1, err}
	return e.mock
}

// Encrypt implements Encrypter
func (mmEncrypt *EncrypterMock) Encrypt(plain []byte) (ba1 []byte, err error) {
	mm_atomic.AddUint64(&mmEncrypt.beforeEncryptCounter, 1)
	defer mm_atomic.AddUint64(&mmEncrypt.afterEncryptCounter, 1)

	if mmEncrypt.inspectFuncEncrypt != nil {
		mmEncrypt.inspectFuncEncrypt(plain)
	}

	mm_params := &EncrypterMockEncryptParams{plain}

	// Record call args
	mmEncrypt.EncryptMock.mutex.Lock()
	mmEncrypt.EncryptMock.callArgs = append(mmEncrypt.EncryptMock.callArgs, mm_params)
	mmEncrypt.EncryptMock.mutex.Unlock()

	for _, e := range mmEncrypt.EncryptMock.expectations {
		if minimock.Equal(e.params, mm_params) {
			mm_atomic.AddUint64(&e.Counter, 1)
			return e.results.ba1, e.results.err
		}
	}

	if mmEncrypt.EncryptMock.defaultExpectation != nil {
		mm_atomic.AddUint64(&mmEncrypt.EncryptMock.defaultExpectation.Counter, 1)
		mm_want := mmEncrypt.EncryptMock.defaultExpectation.params
		mm_got := EncrypterMockEncryptParams{plain}
		if mm_want != nil && !minimock.Equal(*mm_want, mm_got) {
			mmEncrypt.t.Errorf("EncrypterMock.Encrypt got unexpected parameters, want: %#v, got: %#v%s\n", *mm_want, mm_got, minimock.Diff(*mm_want, mm_got))
		}

		mm_results := mmEncrypt.EncryptMock.defaultExpectation.results
		if mm_results == nil {
			mmEncrypt.t.Fatal("No results are set for the EncrypterMock.Encrypt")
		}
		return (*mm_results).ba1, (*mm_results).err
	}
	if mmEncrypt.funcEncrypt != nil {
		return mmEncrypt.funcEncrypt(plain)
	}
	mmEncrypt.t.Fatalf("Unexpected call to EncrypterMock.Encrypt. %v", plain)
	return
}

// EncryptAfterCounter returns a count of finished EncrypterMock.Encrypt invocations
func (mmEncrypt *EncrypterMock) EncryptAfterCounter() uint64 {
	return mm_atomic.LoadUint64(&mmEncrypt.afterEncryptCounter)
}

// EncryptBeforeCounter returns a count of EncrypterMock.Encrypt invocations
func (mmEncrypt *EncrypterMock) EncryptBeforeCounter() uint64 {
	return mm_atomic.LoadUint64(&mmEncrypt.beforeEncryptCounter)
}

// Calls returns a list of arguments used in each call to EncrypterMock.Encrypt.
// The list is in the same order as the calls were made (i.e. recent calls have a higher index)
func (mmEncrypt *mEncrypterMockEncrypt) Calls() []*EncrypterMockEncryptParams {
	mmEncrypt.mutex.RLock()

	argCopy := make([]*EncrypterMockEncryptParams, len(mmEncrypt.callArgs))
	copy(argCopy, mmEncrypt.callArgs)

	mmEncrypt.mutex.RUnlock()

	return argCopy
}

// MinimockEncryptDone returns true if the count of the Encrypt invocations corresponds
// the number of defined expectations
func (m *EncrypterMock) MinimockEncryptDone() bool {
	for _, e := range m.EncryptMock.expectations {
		if mm_atomic.LoadUint64(&e.Counter) < 1 {
			return false
		}
	}

	// if default expectation was set then invocations count should be greater than zero
	if m.EncryptMock.defaultExpectation != nil && mm_atomic.LoadUint64(&m.afterEncryptCounter) < 1 {
		return false
	}
	// if func was set then invocations count should be greater than zero
	if m.funcEncrypt != nil && mm_atomic.LoadUint64(&m.afterEncryptCounter) < 1 {
		return false
	}
	return true
}

// MinimockEncryptInspect logs each unmet expectation
func (m *EncrypterMock) MinimockEncryptInspect() {
	for _, e := range m.EncryptMock.expectations {
		if mm_atomic.LoadUint64(&e.Counter) < 1 {
			m.t.Errorf("Expected call to EncrypterMock.Encrypt with params: %#v", *e.params)
		}
	}

	// if default expectation was set then invocations count should be greater than zero
	if m.EncryptMock.defaultExpectation != nil && mm_atomic.LoadUint64(&m.afterEncryptCounter) < 1 {
		if m.EncryptMock.defaultExpectation.params == nil {
			m.t.Error("Expected call to EncrypterMock.Encrypt")
		} else {
			m.t.Errorf("Expected call to EncrypterMock.Encrypt with params: %#v", *m.EncryptMock.defaultExpectation.params)
		}
	}
	// if func was set then invocations count should be greater than zero
	if m.funcEncrypt != nil && mm_atomic.LoadUint64(&m.afterEncryptCounter) < 1 {
		m.t.Error("Expected call to EncrypterMock.Encrypt")
	}
}

// MinimockFinish checks that all mocked methods have been called the expected number of times
func (m *EncrypterMock) MinimockFinish() {
	if !m.minimockDone() {
		m.MinimockDecryptInspect()

		m.MinimockEncryptInspect()
		m.t.FailNow()
	}
}

// MinimockWait waits for all mocked methods to be called the expected number of times
func (m *EncrypterMock) MinimockWait(timeout mm_time.Duration) {
	timeoutCh := mm_time.After(timeout)
	for {
		if m.minimockDone() {
			return
		}
		select {
		case <-timeoutCh:
			m.MinimockFinish()
			return
		case <-mm_time.After(10 * mm_time.Millisecond):
		}
	}
}

func (m *EncrypterMock) minimockDone() bool {
	done := true
	return done &&
		m.MinimockDecryptDone() &&
		m.MinimockEncryptDone()
}